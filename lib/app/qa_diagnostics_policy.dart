/// Phase 18 / M2 (G3): release gate for the `SAL_QA_DIAG` diagnostics.
///
/// `--dart-define=SAL_QA_DIAG=true` turns on the lock-challenge host's
/// `[SAL_QA]` lines for approved internal QA. Those lines contain the
/// protected package name, so they are allowed in debug and profile builds
/// only: a release build never emits them, even when the define is set.
///
/// Pure Dart (no Flutter import) so the gate can also be checked by an AOT
/// product-mode compile. [kQaReleaseMode] is the same compile-time constant
/// as Flutter's `kReleaseMode` (`dart.vm.product`); a test pins the two
/// together. Both inputs are compile-time constants, so release builds
/// tree-shake the QA logging out.
library;

/// True only in release (product) builds. Equal to Flutter's `kReleaseMode`.
const bool kQaReleaseMode = bool.fromEnvironment('dart.vm.product');

/// True when the build was made with `--dart-define=SAL_QA_DIAG=true`.
const bool kQaDiagnosticsRequested = bool.fromEnvironment('SAL_QA_DIAG');

/// The only switch the app reads: requested AND not a release build.
const bool kQaDiagnosticsEnabled = kQaDiagnosticsRequested && !kQaReleaseMode;

/// The gate as a function, for tests: a release build is never enabled.
bool qaDiagnosticsAllowed({
  required bool requested,
  required bool releaseMode,
}) =>
    requested && !releaseMode;
