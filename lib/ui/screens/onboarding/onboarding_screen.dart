import 'package:flutter/material.dart';

import '../../../app/app_scope.dart';
import '../../../app/router.dart';
import '../../../design_system/design_system.dart';
import '../../../security/credentials/auth_type.dart';
import '../../../security/credentials/biometric_enablement.dart';
import '../../../security/credentials/biometric_options.dart';
import '../../../security/credentials/credential_manager.dart';
import '../../../security/credentials/credential_state.dart';
import '../../../services/biometric_service.dart';
import '../../../utilities/result.dart';
import '../../widgets/secure_storage_unavailable.dart';
import '../pattern/pattern_setup_screen.dart';
import '../pin/pin_setup_screen.dart';
import '../security/app_credential_verification.dart';
import 'onboarding_apps_step.dart';
import 'onboarding_health_step.dart';
import 'onboarding_permissions_step.dart';

/// Onboarding steps: M1 (welcome, authentication, biometric), M2
/// (permissions, apps) and M3 (health check + completion).
enum OnboardingStep {
  welcome,
  authentication,
  biometric,
  permissions,
  apps,
  health,
}

/// First-launch onboarding (Phase 15 / Milestones 1–3):
/// Welcome → PIN/pattern setup → optional biometric activation →
/// permission education and guided setup → optional suggested apps →
/// initial Protection Health check and completion.
///
/// Security rules:
///  * Shown only when no credential exists (see `shouldStartOnboarding`).
///    It is the app's sole initial route, built directly — there is no
///    named route, so no external route name can open it (Phase 6 / M1).
///  * Authentication setup reuses [PinSetupScreen] / [PatternSetupScreen]
///    unchanged (CR-3: initial enrollment only while no credential exists).
///    Their `pop(true)` is NEVER trusted (Phase 5I: enrollment is not
///    authentication); progress is decided by re-reading the credential
///    state.
///  * Biometric activation uses the shared H-3 [enableBiometricUnlock]
///    path: a strong enrolled biometric plus verification of the primary
///    app credential that was just created; device credential never counts.
///  * Permissions and apps (M2) come only after a credential exists; they
///    reuse the existing setup flows and only ADD protection on explicit
///    user selection (see [OnboardingPermissionsStep], [OnboardingAppsStep]).
///  * The completion step (M3) shows "You're Protected" only when the shared
///    Protection Health monitor confirms SECURE in a fresh snapshot; missing
///    setup and unknown status are shown as such (see
///    [classifyOnboardingCompletion]). The outcome never gates leaving.
///  * The onboarding flag is written on completion as a UX record only.
class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});

  static const String welcomeTitle = 'Welcome to Smart App Lock';
  static const String getStartedLabel = 'Get started';
  static const String authTitle = 'Choose how you unlock';
  static const String pinOptionTitle = 'PIN';
  static const String patternOptionTitle = 'Pattern';
  static const String authNotSetMessage =
      'Your PIN or pattern was not saved. Please try again.';
  static const String biometricTitle = 'Unlock with biometrics';
  static const String enableBiometricLabel = 'Enable biometric unlock';
  static const String notNowLabel = 'Not now';
  static const String continueLabel = 'Continue';
  static const String biometricUnavailableText =
      'Biometric unlock isn\'t available on this device right now. You can '
      'turn it on later in Security.';
  static const String biometricNotEnrolledText =
      'No fingerprint or face is enrolled on this device. You can turn on '
      'biometric unlock later in Security after adding one in Android '
      'settings.';
  static const String biometricNotEnabledMessage =
      'Biometric unlock was not enabled.';
  static const String couldNotSaveMessage = 'Could not save. Please try again.';

  /// The onboarding route. Built directly (never via a route name).
  static Route<void> route() => MaterialPageRoute<void>(
        builder: (BuildContext context) => const OnboardingScreen(),
      );

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

/// Biometric step availability.
enum _BiometricAvailability { checking, available, unsupported, notEnrolled }

class _OnboardingScreenState extends State<OnboardingScreen> {
  OnboardingStep _step = OnboardingStep.welcome;
  bool _busy = false;
  String? _message;
  _BiometricAvailability _biometric = _BiometricAvailability.checking;

  CredentialManager? get _auth => AppScope.read(context)?.auth;

  // -- navigation -----------------------------------------------------------

  Future<void> _start() async {
    setState(() {
      _step = OnboardingStep.authentication;
      _message = null;
    });
    // A credential may already exist (e.g. created in another instance);
    // never offer enrollment over it.
    await _advanceIfCredentialExists();
  }

  /// Re-reads the credential state (Phase 5I: never trust a setup pop).
  /// Returns true and moves to the biometric step when a PIN or pattern
  /// now exists.
  Future<bool> _advanceIfCredentialExists() async {
    final CredentialManager? auth = _auth;
    if (auth == null) {
      return false;
    }
    final Result<CredentialState> status = await auth.status();
    if (!mounted) {
      return false;
    }
    final CredentialState? state = status.valueOrNull;
    if (state == null) {
      setState(() => _message = SecureStorageUnavailableText.message);
      return false;
    }
    if (!state.hasAnyCredential) {
      return false;
    }
    setState(() {
      _step = OnboardingStep.biometric;
      _message = null;
      _biometric = _BiometricAvailability.checking;
    });
    await _checkBiometricAvailability();
    return true;
  }

  Future<void> _setUp(AuthType type) async {
    if (_busy) {
      return;
    }
    final CredentialManager? auth = _auth;
    if (auth == null) {
      return;
    }
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      // Refuse to open setup if a credential already exists.
      if (await _advanceIfCredentialExists() || !mounted) {
        return;
      }
      if (_message != null) {
        return; // state unreadable: fail closed, no enrollment
      }
      await Navigator.of(context).push<Object?>(
        MaterialPageRoute<Object?>(
          builder: (BuildContext context) => type == AuthType.pin
              ? PinSetupScreen(credentialManager: auth)
              : PatternSetupScreen(credentialManager: auth),
        ),
      );
      if (!mounted) {
        return;
      }
      // The pop result is ignored; only the stored state counts.
      final bool advanced = await _advanceIfCredentialExists();
      if (!advanced && mounted && _message == null) {
        setState(() => _message = OnboardingScreen.authNotSetMessage);
      }
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }

  Future<void> _checkBiometricAvailability() async {
    final BiometricService? service = AppScope.read(context)?.biometrics;
    _BiometricAvailability result = _BiometricAvailability.unsupported;
    if (service != null) {
      final Result<bool> supported = await service.isSupported();
      if (supported.valueOrNull == true) {
        final Result<Set<BiometricKind>> kinds = await service.availableKinds();
        final Set<BiometricKind>? available = kinds.valueOrNull;
        if (available != null) {
          result = available.contains(BiometricKind.strong)
              ? _BiometricAvailability.available
              : _BiometricAvailability.notEnrolled;
        }
      }
    }
    if (mounted) {
      setState(() => _biometric = result);
    }
  }

  Future<void> _enableBiometric() async {
    if (_busy) {
      return;
    }
    final container = AppScope.read(context);
    if (container == null) {
      return;
    }
    final CredentialManager auth = container.auth;
    setState(() {
      _busy = true;
      _message = null;
    });
    BiometricEnableOutcome outcome = BiometricEnableOutcome.aborted;
    try {
      outcome = await enableBiometricUnlock(
        auth: auth,
        service: container.biometrics,
        verifyPrimary: () async {
          final AppCredentialVerificationResult verification =
              await verifyPrimaryAppCredential(Navigator.of(context), auth);
          return verification.isVerified ? verification.method : null;
        },
        stillActive: () => mounted,
      );
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
    if (!mounted) {
      return;
    }
    switch (outcome) {
      case BiometricEnableOutcome.enabled:
        _goTo(OnboardingStep.permissions);
      case BiometricEnableOutcome.aborted:
        return;
      case BiometricEnableOutcome.unsupported:
        setState(() => _biometric = _BiometricAvailability.unsupported);
      case BiometricEnableOutcome.notEnrolled:
        setState(() => _biometric = _BiometricAvailability.notEnrolled);
      case BiometricEnableOutcome.storageUnavailable:
        setState(() => _message = SecureStorageUnavailableText.message);
      case BiometricEnableOutcome.noCredential:
      case BiometricEnableOutcome.notVerified:
        setState(
          () => _message = OnboardingScreen.biometricNotEnabledMessage,
        );
      case BiometricEnableOutcome.couldNotSave:
        setState(() => _message = OnboardingScreen.couldNotSaveMessage);
    }
  }

  void _goTo(OnboardingStep step) {
    setState(() {
      _step = step;
      _message = null;
    });
  }

  void _toPermissions() => _goTo(OnboardingStep.permissions);

  /// Leaves onboarding for the main shell. Reachable only after the
  /// biometric step, i.e. after a credential was confirmed in storage.
  Future<void> _finish() async {
    final container = AppScope.read(context);
    // UX record only (best effort); never read as a security decision.
    try {
      await container?.preferences.setOnboardingCompleted(true);
    } catch (_) {
      // Non-fatal: launch is decided by credential state.
    }
    if (!mounted) {
      return;
    }
    await Navigator.of(context).pushAndRemoveUntil<dynamic>(
      AppRouter.onGenerateRoute(const RouteSettings(name: RouteNames.home))!,
      (Route<dynamic> route) => false,
    );
  }

  void _back() {
    // Back from authentication returns to welcome and from apps to
    // permissions. The biometric and permission steps have no way back:
    // the credential already exists.
    if (_busy) {
      return;
    }
    if (_step == OnboardingStep.authentication) {
      _goTo(OnboardingStep.welcome);
    } else if (_step == OnboardingStep.apps) {
      _goTo(OnboardingStep.permissions);
    }
  }

  // -- build ----------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: _step == OnboardingStep.welcome,
      onPopInvokedWithResult: (bool didPop, Object? result) {
        if (!didPop) {
          _back();
        }
      },
      child: Scaffold(
        appBar: _step == OnboardingStep.authentication ||
                _step == OnboardingStep.apps
            ? AppBar(
                leading: BackButton(onPressed: _busy ? null : _back),
              )
            : null,
        body: SafeArea(
          child: AnimatedSwitcher(
            duration: const Duration(milliseconds: 200),
            child: switch (_step) {
              OnboardingStep.welcome => _buildWelcome(),
              OnboardingStep.authentication => _buildAuthentication(),
              OnboardingStep.biometric => _buildBiometric(),
              OnboardingStep.permissions => OnboardingPermissionsStep(
                  key: const ValueKey<String>('onboarding_permissions_step'),
                  onContinue: () => _goTo(OnboardingStep.apps),
                ),
              OnboardingStep.apps => OnboardingAppsStep(
                  key: const ValueKey<String>('onboarding_apps_step'),
                  onDone: () => _goTo(OnboardingStep.health),
                ),
              OnboardingStep.health => OnboardingHealthStep(
                  key: const ValueKey<String>('onboarding_health_step'),
                  onFinish: _finish,
                  onReviewSetup: _toPermissions,
                ),
            },
          ),
        ),
      ),
    );
  }

  Widget _buildWelcome() {
    final ThemeData theme = Theme.of(context);
    final DsPalette palette = context.dsColors;
    return ListView(
      key: const ValueKey<String>('onboarding_welcome'),
      padding: DsInsets.screen,
      children: <Widget>[
        const SizedBox(height: DsSpacing.xxl),
        Center(
          child: Container(
            width: 88,
            height: 88,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: palette.primary.withValues(alpha: 0.12),
            ),
            child: Icon(Icons.lock_rounded, size: 44, color: palette.primary),
          ),
        ),
        const SizedBox(height: DsSpacing.xl),
        Text(
          OnboardingScreen.welcomeTitle,
          textAlign: TextAlign.center,
          style: theme.textTheme.headlineSmall,
        ),
        const SizedBox(height: DsSpacing.sm),
        Text(
          'Keep your private apps private. Set up takes about a minute.',
          textAlign: TextAlign.center,
          style: theme.textTheme.bodyMedium?.copyWith(
            color: palette.textSecondary,
          ),
        ),
        const SizedBox(height: DsSpacing.xl),
        const _Point(
          icon: Icons.apps_rounded,
          title: 'Lock the apps you choose',
          body: 'Protected apps ask for your PIN, pattern or biometrics '
              'before they open.',
        ),
        const _Point(
          icon: Icons.phonelink_lock_rounded,
          title: 'Stays on this device',
          body: 'Your PIN or pattern is stored only as a protected hash on '
              'this phone.',
        ),
        const _Point(
          icon: Icons.tune_rounded,
          title: 'You stay in control',
          body: 'Android permissions are explained before you grant them.',
        ),
        const SizedBox(height: DsSpacing.xl),
        DsButton(
          label: OnboardingScreen.getStartedLabel,
          expand: true,
          onPressed: _start,
        ),
      ],
    );
  }

  Widget _buildAuthentication() {
    final ThemeData theme = Theme.of(context);
    final DsPalette palette = context.dsColors;
    final String? message = _message;
    return ListView(
      key: const ValueKey<String>('onboarding_authentication'),
      padding: DsInsets.screen,
      children: <Widget>[
        Text(OnboardingScreen.authTitle, style: theme.textTheme.headlineSmall),
        const SizedBox(height: DsSpacing.sm),
        Text(
          'You\'ll use it to open protected apps and to change Smart App '
          'Lock settings.',
          style: theme.textTheme.bodyMedium?.copyWith(
            color: palette.textSecondary,
          ),
        ),
        if (message != null) ...<Widget>[
          const SizedBox(height: DsSpacing.lg),
          _Notice(message: message),
        ],
        const SizedBox(height: DsSpacing.xl),
        DsCard(
          title: OnboardingScreen.pinOptionTitle,
          subtitle: '4 or 6 digits',
          trailing: Icon(Icons.dialpad_rounded, color: palette.primary),
          onTap: _busy ? null : () => _setUp(AuthType.pin),
        ),
        const SizedBox(height: DsSpacing.md),
        DsCard(
          title: OnboardingScreen.patternOptionTitle,
          subtitle: 'Connect at least 4 dots',
          trailing: Icon(Icons.pattern_rounded, color: palette.primary),
          onTap: _busy ? null : () => _setUp(AuthType.pattern),
        ),
      ],
    );
  }

  Widget _buildBiometric() {
    final ThemeData theme = Theme.of(context);
    final DsPalette palette = context.dsColors;
    final String? message = _message;
    final List<Widget> actions;
    final String body;
    switch (_biometric) {
      case _BiometricAvailability.checking:
        body = '';
        actions = const <Widget>[
          Center(child: CircularProgressIndicator()),
        ];
      case _BiometricAvailability.available:
        body = 'Use your fingerprint or face to open protected apps. Your '
            'PIN or pattern always works too. You\'ll confirm it once to '
            'turn this on.';
        actions = <Widget>[
          DsButton(
            label: OnboardingScreen.enableBiometricLabel,
            expand: true,
            loading: _busy,
            onPressed: _busy ? null : _enableBiometric,
          ),
          const SizedBox(height: DsSpacing.sm),
          DsButton(
            label: OnboardingScreen.notNowLabel,
            variant: DsButtonVariant.ghost,
            expand: true,
            onPressed: _busy ? null : _toPermissions,
          ),
        ];
      case _BiometricAvailability.unsupported:
      case _BiometricAvailability.notEnrolled:
        body = _biometric == _BiometricAvailability.unsupported
            ? OnboardingScreen.biometricUnavailableText
            : OnboardingScreen.biometricNotEnrolledText;
        actions = <Widget>[
          DsButton(
            label: OnboardingScreen.continueLabel,
            expand: true,
            onPressed: _busy ? null : _toPermissions,
          ),
        ];
    }
    return ListView(
      key: const ValueKey<String>('onboarding_biometric'),
      padding: DsInsets.screen,
      children: <Widget>[
        const SizedBox(height: DsSpacing.xxl),
        Center(
          child: Icon(
            Icons.fingerprint_rounded,
            size: 64,
            color: palette.primary,
          ),
        ),
        const SizedBox(height: DsSpacing.xl),
        Text(
          OnboardingScreen.biometricTitle,
          textAlign: TextAlign.center,
          style: theme.textTheme.headlineSmall,
        ),
        const SizedBox(height: DsSpacing.sm),
        Text(
          body,
          textAlign: TextAlign.center,
          style: theme.textTheme.bodyMedium?.copyWith(
            color: palette.textSecondary,
          ),
        ),
        if (message != null) ...<Widget>[
          const SizedBox(height: DsSpacing.lg),
          _Notice(message: message),
        ],
        const SizedBox(height: DsSpacing.xl),
        ...actions,
      ],
    );
  }
}

class _Point extends StatelessWidget {
  const _Point({required this.icon, required this.title, required this.body});

  final IconData icon;
  final String title;
  final String body;

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    final DsPalette palette = context.dsColors;
    return Padding(
      padding: const EdgeInsets.only(bottom: DsSpacing.lg),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Icon(icon, color: palette.primary),
          const SizedBox(width: DsSpacing.md),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(title, style: theme.textTheme.titleSmall),
                const SizedBox(height: 2),
                Text(
                  body,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: palette.textSecondary,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _Notice extends StatelessWidget {
  const _Notice({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    final DsPalette palette = context.dsColors;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: palette.warning.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(DsRadii.md),
        border: Border.all(color: palette.warning.withValues(alpha: 0.35)),
      ),
      child: Row(
        children: <Widget>[
          Icon(Icons.info_outline, size: 18, color: palette.warning),
          const SizedBox(width: DsSpacing.sm),
          Expanded(
            child: Text(message, style: theme.textTheme.bodySmall),
          ),
        ],
      ),
    );
  }
}
