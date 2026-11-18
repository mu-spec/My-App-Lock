import 'package:flutter/material.dart';

import '../../../app/app_scope.dart';
import '../../../design_system/design_system.dart';
import '../../../protection/health/protection_health_engine.dart';
import '../../../protection/health/protection_health_monitor.dart';
import '../health/health_presentation.dart';
import '../health/health_resume_trigger.dart';
import '../health/protection_health_controller.dart';

/// Outcome of the first Protection Health check (Phase 15 / M3).
enum OnboardingCompletion {
  /// Android positively confirmed every protection component working in a
  /// fresh snapshot (engine state SECURE, not stale).
  protectionActive,

  /// A required permission or setup step is confirmed missing (not
  /// granted, revoked, no protected apps, background restricted).
  setupIncomplete,

  /// Protection could not be confirmed (no report, failed or stale check,
  /// unknown or interrupted component). Never shown as active.
  unableToVerify,
}

/// Issue categories that mean "the user still has setup to do".
const Set<HealthIssueCategory> _setupCategories = <HealthIssueCategory>{
  HealthIssueCategory.setup,
  HealthIssueCategory.userChoice,
  HealthIssueCategory.revoked,
  HealthIssueCategory.restricted,
};

/// Pure classification of a Protection Health report for onboarding.
///
/// Fail-closed precedence:
///  1. no report / failed check → [OnboardingCompletion.unableToVerify];
///  2. SECURE and fresh → [OnboardingCompletion.protectionActive] (the only
///     path to "active");
///  3. any confirmed missing setup → [OnboardingCompletion.setupIncomplete]
///     (even when other signals are unknown: the gap is real);
///  4. anything else (unknown, stale, interrupted) →
///     [OnboardingCompletion.unableToVerify].
OnboardingCompletion classifyOnboardingCompletion(
  ProtectionHealthReport? report, {
  bool failed = false,
}) {
  if (failed || report == null) {
    return OnboardingCompletion.unableToVerify;
  }
  if (report.state == ProtectionHealthState.secure && !report.stale) {
    return OnboardingCompletion.protectionActive;
  }
  final bool setupMissing = report.issues.any(
    (HealthIssue i) =>
        i.severity != HealthIssueSeverity.advisory &&
        _setupCategories.contains(i.category),
  );
  return setupMissing
      ? OnboardingCompletion.setupIncomplete
      : OnboardingCompletion.unableToVerify;
}

/// Phase 15 / M3 — Initial Health Check and Setup Complete.
///
/// Runs one after-change refresh through the app's single shared
/// [ProtectionHealthMonitor] (no second classifier) and shows exactly one
/// of three outcomes. "You're Protected" appears only for
/// [OnboardingCompletion.protectionActive]; the view re-classifies whenever
/// the controller notifies (including when the report ages out), so a
/// stale SECURE turns into "Unable to verify". Observational only: it never
/// grants, starts or arms anything.
class OnboardingHealthStep extends StatefulWidget {
  const OnboardingHealthStep({
    super.key,
    required this.onFinish,
    required this.onReviewSetup,
    @visibleForTesting this.debugMonitor,
  });

  /// Leaves onboarding (always available; the outcome is not a gate).
  final VoidCallback onFinish;

  /// Returns to the permission step to fix missing setup.
  final VoidCallback onReviewSetup;

  /// Test-only clock seam. Production always uses the app's shared
  /// `AppContainer.protectionHealth` monitor.
  final ProtectionHealthMonitor? debugMonitor;

  static const String checkingTitle = 'Checking protection…';
  static const String activeTitle = "You're Protected";
  static const String activeLabel = 'Protection Active';
  static const String activeMessage =
      'Android confirmed that every protection check passed. Protected apps '
      'will ask for your PIN, pattern or biometrics.';
  static const String incompleteTitle = 'Setup Incomplete';
  static const String incompleteMessage =
      'Some required permissions or setup steps are missing, so protected '
      'apps may not lock yet.';
  static const String unableTitle = 'Unable to Verify';
  static const String unableMessage =
      "Smart App Lock couldn't confirm that protection is working. This "
      'does not mean it is working. Check again, or open Protection Health '
      'from the Home tab later.';
  static const String checkAgainLabel = 'Check again';
  static const String reviewSetupLabel = 'Review setup';
  static const String finishLabel = 'Go to Smart App Lock';
  static const String finishAnywayLabel = 'Finish for now';

  @override
  State<OnboardingHealthStep> createState() => _OnboardingHealthStepState();
}

class _OnboardingHealthStepState extends State<OnboardingHealthStep> {
  ProtectionHealthController? _controller;

  /// False until this step's own first refresh settles: an earlier
  /// observation (e.g. from app start) is never shown as the result.
  bool _firstCheckDone = false;
  late final HealthResumeTrigger _resume = HealthResumeTrigger(
    onResumed: ({required bool returned}) =>
        _controller?.refresh(afterChange: true),
  );

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_controller != null) {
      return;
    }
    final ProtectionHealthController controller = ProtectionHealthController(
      widget.debugMonitor ?? AppScope.read(context)?.protectionHealth,
    )..addListener(_onChanged);
    _controller = controller;
    _resume.attach();
    if (!controller.available) {
      _firstCheckDone = true;
      return;
    }
    // A fresh observation: never reuse an earlier collection.
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      await controller.refresh(afterChange: true);
      if (mounted) setState(() => _firstCheckDone = true);
    });
  }

  @override
  void dispose() {
    _resume.detach();
    _controller
      ?..removeListener(_onChanged)
      ..dispose();
    super.dispose();
  }

  void _onChanged() {
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    final DsPalette palette = context.dsColors;
    final ProtectionHealthController controller = _controller!;
    final ProtectionHealthReport? report = controller.report;
    final bool checking = !_firstCheckDone ||
        (controller.available && report == null && !controller.failed);

    if (checking) {
      return ListView(
        key: const ValueKey<String>('onboarding_health_checking'),
        padding: DsInsets.screen,
        children: <Widget>[
          const SizedBox(height: DsSpacing.xxl),
          const Center(child: CircularProgressIndicator()),
          const SizedBox(height: DsSpacing.lg),
          Text(
            OnboardingHealthStep.checkingTitle,
            textAlign: TextAlign.center,
            style: theme.textTheme.titleMedium,
          ),
        ],
      );
    }

    final OnboardingCompletion outcome = classifyOnboardingCompletion(
      report,
      failed: controller.failed || !controller.available,
    );
    final (IconData icon, Color color, String title, String message) =
        switch (outcome) {
      OnboardingCompletion.protectionActive => (
          Icons.verified_user_rounded,
          palette.success,
          OnboardingHealthStep.activeTitle,
          OnboardingHealthStep.activeMessage,
        ),
      OnboardingCompletion.setupIncomplete => (
          Icons.warning_amber_rounded,
          palette.warning,
          OnboardingHealthStep.incompleteTitle,
          OnboardingHealthStep.incompleteMessage,
        ),
      OnboardingCompletion.unableToVerify => (
          Icons.help_outline_rounded,
          palette.warning,
          OnboardingHealthStep.unableTitle,
          OnboardingHealthStep.unableMessage,
        ),
    };
    final List<HealthIssue> issues =
        outcome == OnboardingCompletion.protectionActive || report == null
            ? const <HealthIssue>[]
            : report.issues
                .where((HealthIssue i) =>
                    i.severity != HealthIssueSeverity.advisory)
                .take(4)
                .toList();

    return ListView(
      key: ValueKey<String>('onboarding_health_${outcome.name}'),
      padding: DsInsets.screen,
      children: <Widget>[
        const SizedBox(height: DsSpacing.xxl),
        Center(child: Icon(icon, size: 72, color: color)),
        const SizedBox(height: DsSpacing.lg),
        Text(
          title,
          key: const Key('onboarding_health_title'),
          textAlign: TextAlign.center,
          style: theme.textTheme.headlineSmall,
        ),
        if (outcome == OnboardingCompletion.protectionActive) ...<Widget>[
          const SizedBox(height: DsSpacing.sm),
          const Center(
            child: DsStatusPill(
              label: OnboardingHealthStep.activeLabel,
              tone: DsTone.success,
            ),
          ),
        ],
        const SizedBox(height: DsSpacing.sm),
        Text(
          message,
          textAlign: TextAlign.center,
          style: theme.textTheme.bodyMedium?.copyWith(
            color: palette.textSecondary,
          ),
        ),
        if (outcome == OnboardingCompletion.protectionActive) ...<Widget>[
          const SizedBox(height: DsSpacing.md),
          Text(
            HealthPresentation.secureScope,
            textAlign: TextAlign.center,
            style: theme.textTheme.bodySmall?.copyWith(
              color: palette.textSecondary,
            ),
          ),
        ],
        if (issues.isNotEmpty) ...<Widget>[
          const SizedBox(height: DsSpacing.lg),
          for (final HealthIssue issue in issues)
            Padding(
              padding: const EdgeInsets.only(bottom: DsSpacing.sm),
              child: DsCard(
                key: Key('onboarding_health_issue_${issue.code.id}'),
                title: HealthPresentation.issue(issue).title,
                subtitle: HealthPresentation.issue(issue).explanation,
              ),
            ),
        ],
        const SizedBox(height: DsSpacing.xl),
        if (outcome == OnboardingCompletion.protectionActive)
          DsButton(
            label: OnboardingHealthStep.finishLabel,
            expand: true,
            onPressed: widget.onFinish,
          )
        else ...<Widget>[
          if (outcome == OnboardingCompletion.setupIncomplete)
            DsButton(
              label: OnboardingHealthStep.reviewSetupLabel,
              expand: true,
              onPressed: controller.checking ? null : widget.onReviewSetup,
            ),
          if (outcome == OnboardingCompletion.unableToVerify)
            DsButton(
              label: OnboardingHealthStep.checkAgainLabel,
              expand: true,
              loading: controller.checking,
              onPressed: controller.checking || !controller.available
                  ? null
                  : () => controller.refresh(afterChange: true),
            ),
          const SizedBox(height: DsSpacing.sm),
          DsButton(
            label: OnboardingHealthStep.finishAnywayLabel,
            variant: DsButtonVariant.ghost,
            expand: true,
            onPressed: widget.onFinish,
          ),
        ],
      ],
    );
  }
}
