import '../../../security/credentials/credential_manager.dart';
import '../../../security/credentials/credential_state.dart';
import '../../../utilities/result.dart';

/// Phase 15 / M1: whether the app should start in onboarding.
///
/// Decided from the CREDENTIAL STATE only: onboarding is shown exactly when
/// the state is readable and no PIN or pattern exists. The onboarding
/// preference flag is a UX record, never consulted here and never a
/// security gate:
///  * an existing credential always starts at the main shell, so onboarding
///    can never be used to re-enroll (enrollment is CR-3 gated anyway);
///  * an unreadable state (secure storage unavailable) starts at the main
///    shell, which already shows the fail-closed storage-unavailable UI —
///    onboarding never attempts enrollment over storage it cannot read.
Future<bool> shouldStartOnboarding(CredentialManager auth) async {
  final Result<CredentialState> status = await auth.status();
  final CredentialState? state = status.valueOrNull;
  return state != null && !state.hasAnyCredential;
}
