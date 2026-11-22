import 'package:flutter/services.dart';

import '../../security/credentials/biometric_binding.dart';
import '../../security/credentials/biometric_options.dart';
import '../../utilities/result.dart';
import '../biometric_service.dart';
import 'local_auth_biometric_service.dart';

/// Phase 18 / M1F (F18-3, owner-approved Option B): production
/// [BiometricService] whose unlock prompt is bound to the Keystore key of
/// [BiometricBinding] (`BiometricBindingChannel.kt`):
///  * BiometricPrompt with a CryptoObject over that key;
///  * BIOMETRIC_STRONG (Class 3) only — never a device credential;
///  * success only when the key completed an encryption in the keystore, so
///    a biometric enrolled after enablement (which invalidates the key) can
///    never unlock.
/// Capability queries ([isSupported], [availableKinds]) are unchanged
/// (local_auth). Every platform problem fails closed with a code-carrying
/// [BiometricAuthException]; nothing is fabricated.
class KeyBoundBiometricService implements BiometricService, BiometricBinding {
  KeyBoundBiometricService({
    BiometricService? capabilities,
    MethodChannel channel = const MethodChannel(channelName),
  })  : _capabilities = capabilities ?? LocalAuthBiometricService(),
        _channel = channel;

  static const String channelName = 'smart_app_lock/biometric_binding';

  final BiometricService _capabilities;
  final MethodChannel _channel;

  @override
  Future<Result<bool>> isSupported() => _capabilities.isSupported();

  @override
  Future<Result<Set<BiometricKind>>> availableKinds() =>
      _capabilities.availableKinds();

  @override
  Future<Result<bool>> authenticate({
    required String reason,
    BiometricOptions? options,
  }) async {
    final BiometricOptions opts = options ?? BiometricOptions.defaults;
    try {
      final bool? ok = await _channel.invokeMethod<bool>(
        'authenticate',
        <String, Object?>{
          'reason': reason,
          // H-3: `allowDeviceCredential` is deliberately never sent; the
          // native prompt allows BIOMETRIC_STRONG only.
          'requireConfirmation': opts.requireConfirmation,
        },
      );
      if (ok == true) return Result.success(true);
      return Result.failure(bindingError('deviceError'));
    } on PlatformException catch (e) {
      return Result.failure(bindingError(e.code));
    } on MissingPluginException {
      return Result.failure(bindingError('uiUnavailable'));
    } on Object {
      return Result.failure(bindingError('unknown'));
    }
  }

  @override
  Future<bool> createKey() async {
    try {
      return await _channel.invokeMethod<bool>('createKey') == true;
    } on Object {
      return false;
    }
  }

  @override
  Future<BiometricKeyState> checkKey() async {
    try {
      final String? state = await _channel.invokeMethod<String>('checkKey');
      return switch (state) {
        'valid' => BiometricKeyState.valid,
        'invalidated' => BiometricKeyState.invalidated,
        'missing' => BiometricKeyState.missing,
        _ => BiometricKeyState.error,
      };
    } on Object {
      return BiometricKeyState.error;
    }
  }

  @override
  Future<void> deleteKey() async {
    try {
      await _channel.invokeMethod<void>('deleteKey');
    } on Object {
      // Best effort.
    }
  }
}

/// Native code → user-safe exception (no platform text is ever exposed).
BiometricAuthException bindingError(String code) {
  final String message = switch (code) {
    BiometricAuthException.keyInvalidatedCode =>
      'Biometrics changed on this device. Enable biometric unlock again.',
    'userCanceled' => 'Biometric authentication was cancelled.',
    'systemCanceled' => 'Biometric authentication was cancelled by the system.',
    'timeout' => 'Biometric authentication timed out.',
    'temporaryLockout' => 'Biometric authentication is temporarily locked out.',
    'biometricLockout' =>
      'Biometric authentication is locked. Unlock with another method.',
    'noBiometricsEnrolled' =>
      'No biometric credential is enrolled on this device.',
    'noBiometricHardware' => 'Biometric hardware is not available.',
    'biometricHardwareTemporarilyUnavailable' =>
      'Biometric hardware is temporarily unavailable.',
    'noCredentialsSet' => 'No device credential is configured.',
    'authInProgress' => 'An authentication is already in progress.',
    'uiUnavailable' => 'The biometric prompt is unavailable right now.',
    _ => 'Biometric authentication failed.',
  };
  const Set<String> known = <String>{
    BiometricAuthException.keyInvalidatedCode,
    'userCanceled',
    'systemCanceled',
    'timeout',
    'temporaryLockout',
    'biometricLockout',
    'noBiometricsEnrolled',
    'noBiometricHardware',
    'biometricHardwareTemporarilyUnavailable',
    'noCredentialsSet',
    'authInProgress',
    'uiUnavailable',
    'deviceError',
  };
  return BiometricAuthException(
    code: known.contains(code) ? code : 'unknown',
    message: message,
  );
}
