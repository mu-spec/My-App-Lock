import 'package:flutter/material.dart';

import '../../../app/app_scope.dart';
import '../../../data/models/app_entry.dart';
import '../../../data/models/protected_app.dart';
import '../../../data/models/security_recommendation.dart';
import '../../../design_system/design_system.dart';
import '../../../utilities/result.dart';

/// An installed app suggested for protection.
class OnboardingAppSuggestion {
  const OnboardingAppSuggestion({required this.app, required this.category});

  final AppEntry app;
  final SensitiveAppCategory category;
}

/// Installed apps that appear in the reviewed Phase 8 catalog
/// ([SecurityRecommendations.catalog], exact package names only), ordered
/// by catalog category, then label. Pure: nothing is stored, logged or sent.
List<OnboardingAppSuggestion> onboardingSuggestions(List<AppEntry> installed) {
  final List<OnboardingAppSuggestion> out = <OnboardingAppSuggestion>[];
  final Set<String> seen = <String>{};
  for (final AppEntry app in installed) {
    final SensitiveAppCategory? category =
        SecurityRecommendations.catalog[app.packageName];
    if (category != null && seen.add(app.packageName)) {
      out.add(OnboardingAppSuggestion(app: app, category: category));
    }
  }
  out.sort((OnboardingAppSuggestion a, OnboardingAppSuggestion b) {
    final int byCategory = a.category.index.compareTo(b.category.index);
    return byCategory != 0
        ? byCategory
        : a.app.label.toLowerCase().compareTo(b.app.label.toLowerCase());
  });
  return out;
}

/// Phase 15 / M2 — optional suggested apps.
///
/// Suggestions start UNSELECTED. Apps are protected only when the user
/// selects them and taps the explicit "Protect" button; skipping protects
/// nothing. Onboarding only ADDS protection (at the default level, through
/// the same repository + bootstrap sync as the Apps tab); it never removes
/// or downgrades anything (removal stays behind CR-2 in the Apps tab).
/// An unreadable protection set fails closed: no suggestion is offered and
/// nothing is written. The installed-app list stays in memory only.
class OnboardingAppsStep extends StatefulWidget {
  const OnboardingAppsStep({super.key, required this.onDone});

  final VoidCallback onDone;

  static const String title = 'Protect your private apps';
  static const String subtitle =
      'These apps on your phone often hold money, passwords or private '
      'messages. Choose any you want to lock — or skip and pick apps later '
      'in the Apps tab.';
  static const String noneFoundText =
      'No commonly sensitive apps were found. You can protect any app later '
      'in the Apps tab.';
  static const String loadFailedText =
      "Couldn't load your apps. Nothing was protected. You can choose apps "
      'later in the Apps tab.';
  static const String retryLabel = 'Try again';
  static const String skipLabel = 'Skip';
  static const String continueLabel = 'Continue';
  static const String alreadyProtectedLabel = 'Protected';
  static String protectLabel(int n) =>
      n == 1 ? 'Protect 1 app' : 'Protect $n apps';
  static String partialFailure(int n) => n == 1
      ? "1 app couldn't be protected. Try again or continue."
      : "$n apps couldn't be protected. Try again or continue.";

  @override
  State<OnboardingAppsStep> createState() => _OnboardingAppsStepState();
}

enum _LoadState { loading, ready, error }

class _OnboardingAppsStepState extends State<OnboardingAppsStep> {
  _LoadState _state = _LoadState.loading;
  List<OnboardingAppSuggestion> _suggestions = <OnboardingAppSuggestion>[];
  Set<String> _protected = <String>{};
  Set<String> _selected = <String>{};
  bool _busy = false;
  String? _message;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  Future<void> _load() async {
    if (!mounted) {
      return;
    }
    setState(() {
      _state = _LoadState.loading;
      _message = null;
    });
    final container = AppScope.read(context);
    if (container == null) {
      setState(() => _state = _LoadState.error);
      return;
    }
    final Result<List<AppEntry>> apps =
        await container.installedApps.getInstalledApps();
    final Result<List<ProtectedApp>> protected =
        await container.protectedApps.getProtectedApps();
    if (!mounted) {
      return;
    }
    // Never treat an unknown protection set as "nothing protected".
    if (apps.isFailure || protected.isFailure) {
      setState(() => _state = _LoadState.error);
      return;
    }
    setState(() {
      _suggestions = onboardingSuggestions(apps.valueOrNull!);
      _protected =
          protected.valueOrNull!.map((ProtectedApp p) => p.packageName).toSet();
      _selected = <String>{};
      _state = _LoadState.ready;
    });
  }

  void _toggle(String pkg) {
    if (_busy || _protected.contains(pkg)) {
      return;
    }
    setState(() {
      _selected.contains(pkg) ? _selected.remove(pkg) : _selected.add(pkg);
      _message = null;
    });
  }

  /// Explicit user action: protects exactly the selected apps.
  Future<void> _protectSelected() async {
    final container = AppScope.read(context);
    if (container == null || _busy || _selected.isEmpty) {
      return;
    }
    setState(() {
      _busy = true;
      _message = null;
    });
    // Re-read the protection set right before writing; skip anything
    // already protected (never re-add / reset an existing record).
    final Result<List<ProtectedApp>> current =
        await container.protectedApps.getProtectedApps();
    if (!mounted) {
      return;
    }
    if (current.isFailure) {
      setState(() {
        _busy = false;
        _state = _LoadState.error;
      });
      return;
    }
    final Set<String> alreadyProtected =
        current.valueOrNull!.map((ProtectedApp p) => p.packageName).toSet();
    final Set<String> succeeded = <String>{};
    final Set<String> failed = <String>{};
    for (final OnboardingAppSuggestion s in _suggestions) {
      final String pkg = s.app.packageName;
      if (!_selected.contains(pkg) || alreadyProtected.contains(pkg)) {
        continue;
      }
      final Result<void> added = await container.protectedApps.add(
        ProtectedApp(
          packageName: pkg,
          label: s.app.label,
          addedAt: DateTime.now(),
        ),
      );
      added.isSuccess ? succeeded.add(pkg) : failed.add(pkg);
    }
    if (succeeded.isNotEmpty) {
      await container.protectionBootstrap.synchronize();
    }
    if (!mounted) {
      return;
    }
    if (failed.isNotEmpty) {
      setState(() {
        _protected = <String>{...alreadyProtected, ...succeeded};
        _selected = failed;
        _busy = false;
        _message = OnboardingAppsStep.partialFailure(failed.length);
      });
      return;
    }
    setState(() => _busy = false);
    widget.onDone();
  }

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    final DsPalette palette = context.dsColors;
    final List<Widget> body;
    switch (_state) {
      case _LoadState.loading:
        body = const <Widget>[
          SizedBox(height: DsSpacing.xl),
          Center(child: CircularProgressIndicator()),
        ];
      case _LoadState.error:
        body = <Widget>[
          Text(OnboardingAppsStep.loadFailedText,
              style: theme.textTheme.bodyMedium),
          const SizedBox(height: DsSpacing.lg),
          DsButton(
            label: OnboardingAppsStep.retryLabel,
            variant: DsButtonVariant.outline,
            expand: true,
            onPressed: _load,
          ),
          const SizedBox(height: DsSpacing.sm),
          DsButton(
            label: OnboardingAppsStep.continueLabel,
            expand: true,
            onPressed: widget.onDone,
          ),
        ];
      case _LoadState.ready:
        final List<OnboardingAppSuggestion> selectable = _suggestions
            .where((OnboardingAppSuggestion s) =>
                !_protected.contains(s.app.packageName))
            .toList();
        final int count = _selected.length;
        final String? message = _message;
        body = <Widget>[
          if (_suggestions.isEmpty)
            Text(OnboardingAppsStep.noneFoundText,
                style: theme.textTheme.bodyMedium)
          else
            for (final OnboardingAppSuggestion s in _suggestions)
              _SuggestionTile(
                suggestion: s,
                protected: _protected.contains(s.app.packageName),
                selected: _selected.contains(s.app.packageName),
                enabled: !_busy,
                onTap: () => _toggle(s.app.packageName),
              ),
          if (message != null) ...<Widget>[
            const SizedBox(height: DsSpacing.md),
            Text(message, style: TextStyle(color: palette.danger)),
          ],
          const SizedBox(height: DsSpacing.xl),
          if (selectable.isNotEmpty) ...<Widget>[
            DsButton(
              key: const Key('onboarding_protect_selected'),
              label: count == 0
                  ? OnboardingAppsStep.protectLabel(0)
                  : OnboardingAppsStep.protectLabel(count),
              expand: true,
              loading: _busy,
              onPressed: count == 0 || _busy ? null : _protectSelected,
            ),
            const SizedBox(height: DsSpacing.sm),
            DsButton(
              label: OnboardingAppsStep.skipLabel,
              variant: DsButtonVariant.ghost,
              expand: true,
              onPressed: _busy ? null : widget.onDone,
            ),
          ] else
            DsButton(
              label: OnboardingAppsStep.continueLabel,
              expand: true,
              onPressed: _busy ? null : widget.onDone,
            ),
        ];
    }
    return ListView(
      key: const ValueKey<String>('onboarding_apps'),
      padding: DsInsets.screen,
      children: <Widget>[
        Text(OnboardingAppsStep.title, style: theme.textTheme.headlineSmall),
        const SizedBox(height: DsSpacing.sm),
        Text(
          OnboardingAppsStep.subtitle,
          style: theme.textTheme.bodyMedium?.copyWith(
            color: palette.textSecondary,
          ),
        ),
        const SizedBox(height: DsSpacing.xl),
        ...body,
      ],
    );
  }
}

class _SuggestionTile extends StatelessWidget {
  const _SuggestionTile({
    required this.suggestion,
    required this.protected,
    required this.selected,
    required this.enabled,
    required this.onTap,
  });

  final OnboardingAppSuggestion suggestion;
  final bool protected;
  final bool selected;
  final bool enabled;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final DsPalette palette = context.dsColors;
    final String pkg = suggestion.app.packageName;
    return Padding(
      padding: const EdgeInsets.only(bottom: DsSpacing.sm),
      child: DsCard(
        key: Key('onboarding_app_$pkg'),
        title: suggestion.app.label,
        subtitle: suggestion.category.reason,
        color: selected ? palette.primary.withValues(alpha: 0.12) : null,
        trailing: protected
            ? const DsStatusPill(
                label: OnboardingAppsStep.alreadyProtectedLabel,
                tone: DsTone.success,
              )
            : Icon(
                selected ? Icons.check_box : Icons.check_box_outline_blank,
                color: selected ? palette.primary : palette.border,
              ),
        onTap: protected || !enabled ? null : onTap,
      ),
    );
  }
}
