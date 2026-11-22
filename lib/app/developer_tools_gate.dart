import 'package:flutter/foundation.dart';

/// Phase 18 / M1F (F18-5 proposal): the temporary Phase 5B developer tools
/// (the Home "Developer" card and the Detection diagnostics route) exist
/// only in debug builds.
///
/// [kReleaseMode] is a compile-time constant, so in a release build this
/// getter folds to `false` before the override is consulted: no test hook
/// can re-enable the tools there, and the diagnostics screen becomes
/// unreachable code. Profile builds also hide them ([kDebugMode] is false).
bool get developerDiagnosticsEnabled {
  if (kReleaseMode) return false;
  return debugDeveloperDiagnosticsOverride ?? kDebugMode;
}

/// Test-only: simulates a non-debug build in host tests (which always run
/// in debug mode). Ignored in release builds.
@visibleForTesting
bool? debugDeveloperDiagnosticsOverride;
