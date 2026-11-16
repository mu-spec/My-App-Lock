/// P13/M3 NF-NS-1: failures of the credential state transitions.
///
/// Each is returned as a `Result.failure` — never as an `AuthAttemptResult`
/// — so no verdict is ever released with them: nothing unlocks, no grant is
/// issued, and the response is identical whether or not the entered
/// credential matched. They carry no credential or settings data.
library;

/// Base type of the credential state failures below.
sealed class CredentialStateFailure implements Exception {
  const CredentialStateFailure();
}

/// The stored credential changed (another manager, engine or process
/// committed a PIN/pattern change or Clear All) while this attempt was
/// being verified. The attempt is not counted (the owner did not cause the
/// race) and never succeeds (the verified credential is gone).
final class CredentialChangedDuringVerification extends CredentialStateFailure {
  const CredentialChangedDuringVerification();

  @override
  String toString() => 'CredentialChangedDuringVerification';
}

/// Every bounded compare-and-set attempt lost to a concurrent writer. The
/// operation did not take effect; fail closed.
final class CredentialStateConflict extends CredentialStateFailure {
  const CredentialStateConflict();

  @override
  String toString() => 'CredentialStateConflict';
}

/// The commit outcome could not be confirmed (busy, closed or failed
/// storage; the reconciliation read did not show the write landed). No
/// verdict is released; the attempt may or may not have been counted.
final class CredentialStateUnknown extends CredentialStateFailure {
  const CredentialStateUnknown();

  @override
  String toString() => 'CredentialStateUnknown';
}

/// A computed next state would weaken the durable state it was derived
/// from (lower counters, a dropped lockout, a changed credential set in a
/// verdict commit). Defence in depth: nothing is written.
final class CredentialStateRegression extends CredentialStateFailure {
  const CredentialStateRegression(this.rule);

  /// Fixed rule name only.
  final String rule;

  @override
  String toString() => 'CredentialStateRegression($rule)';
}
