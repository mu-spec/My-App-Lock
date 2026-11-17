import 'package:flutter/material.dart';

import 'app/app.dart';
import 'app/app_container.dart';
import 'ui/screens/onboarding/onboarding_decision.dart';

/// Smart App Lock — application entry point.
///
/// Boots the persistence layer (Phase 1E: shared_preferences + SQLite)
/// before the first frame, then hands the container to the widget tree so
/// later phases can resolve repositories anywhere.
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final AppContainer container = await AppContainer.create();
  // Phase 15 / M1: first launch (no PIN or pattern yet) starts onboarding.
  final bool onboarding = await shouldStartOnboarding(container.auth);
  runApp(
    SmartAppLockApp(container: container, startWithOnboarding: onboarding),
  );
}
