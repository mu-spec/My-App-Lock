// Phase 18 / M1F — F18-3 (owner-approved Option B): biometric unlock is
// bound to an Android Keystore key that Android invalidates when a new
// biometric is enrolled. After a change, biometric unlock turns off and can
// only be re-enabled through the Smart App Lock PIN/pattern. No device
// credential fallback.
//
// SIMULATED (evidence B) for the Dart flows (production manager +
// repository, fake key-bound service) and STATIC (evidence C) for the
// native contract. Real Keystore invalidation, BiometricPrompt behaviour
// and OEM differences are DEVICE PENDING.
//
//  BB1  valid key: the prompt runs, success unlocks
//  BB2  invalidated key: biometric unlock off (persisted), key deleted,
//       no prompt, nothing counted
//  BB3  missing key (legacy, D3-b): treated like invalidated
//  BB4  keystore error: unavailable for this attempt, nothing changed
//  BB5  key invalidated at prompt time: off, not counted
//  BB6  enable flow: key created after verification, before saving; no key
//       = not enabled
//  BB7  re-enabling after a change needs the app PIN/pattern
//  BB8  Dart bridge: exact arguments, error-code mapping, fail closed
//  BB9  native contract: BIOMETRIC_STRONG + CryptoObject only, key
//       invalidated by enrollment, success needs cipher output
//  BB10 production wiring
import 'dart:io';
import 'dart:math';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/repositories/impl/security_settings_repository_impl.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/biometric_binding.dart';
import 'package:smart_app_lock/security/credentials/biometric_enablement.dart';
import 'package:smart_app_lock/security/credentials/biometric_options.dart';
import 'package:smart_app_lock/security/credentials/credential_state_machine.dart';
import 'package:smart_app_lock/security/credentials/impl/default_credential_manager.dart';
import 'package:smart_app_lock/security/credentials/pattern_hasher.dart';
import 'package:smart_app_lock/security/pin_hasher.dart';
import 'package:smart_app_lock/services/biometric_service.dart';
import 'package:smart_app_lock/services/impl/key_bound_biometric_service.dart';
import 'package:smart_app_lock/utilities/result.dart';

const String _pin = '739154';
const BiometricOptions _enabled = BiometricOptions(
  allowStrongBiometrics: true,
  allowDeviceCredential: false,
  requireConfirmation: true,
);

class _FakeKeyBound implements BiometricService, BiometricBinding {
  BiometricKeyState state = BiometricKeyState.valid;
  bool createResult = true;
  Result<bool> promptResult = Result.success(true);
  final List<String> calls = <String>[];
  void Function()? onCreate;

  @override
  Future<Result<bool>> isSupported() async => Result.success(true);

  @override
  Future<Result<Set<BiometricKind>>> availableKinds() async =>
      Result.success(<BiometricKind>{BiometricKind.strong});

  @override
  Future<Result<bool>> authenticate({
    required String reason,
    BiometricOptions? options,
  }) async {
    calls.add('prompt');
    return promptResult;
  }

  @override
  Future<BiometricKeyState> checkKey() async {
    calls.add('check');
    return state;
  }

  @override
  Future<bool> createKey() async {
    calls.add('create');
    onCreate?.call();
    if (createResult) state = BiometricKeyState.valid;
    return createResult;
  }

  @override
  Future<void> deleteKey() async {
    calls.add('delete');
    state = BiometricKeyState.missing;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late InMemoryLocalDatabase db;
  late _FakeKeyBound bio;
  final DateTime now = DateTime(2026, 10, 22, 9);

  DefaultCredentialManager manager() => DefaultCredentialManager(
        settings: SecuritySettingsRepositoryImpl(db),
        pinHasher: Pbkdf2PinHasher(iterations: 200, random: Random(18)),
        patternHasher: Pbkdf2PatternHasher(iterations: 200, random: Random(81)),
        stateMachine: CredentialStateMachine(
          maxFailedAttempts: 3,
          lockoutDuration: const Duration(seconds: 30),
        ),
        biometricService: bio,
        now: () => now,
      );

  Future<BiometricOptions?> storedOptions() async =>
      (await SecuritySettingsRepositoryImpl(db).getSettings())
          .valueOrNull!
          .biometricOptions;

  Future<int> storedFailures() async =>
      (await SecuritySettingsRepositoryImpl(db).getSettings())
          .valueOrNull!
          .failedAttempts;

  Future<DefaultCredentialManager> enabledManager() async {
    final DefaultCredentialManager m = manager();
    expect((await m.enrollPin(_pin)).isSuccess, isTrue);
    expect((await m.updateBiometricOptions(_enabled)).isSuccess, isTrue);
    return m;
  }

  setUp(() {
    db = InMemoryLocalDatabase();
    bio = _FakeKeyBound();
  });

  group('F18-3 unlock', () {
    test('BB1 valid key: the prompt runs and success unlocks', () async {
      final DefaultCredentialManager m = await enabledManager();
      final AuthAttemptResult r =
          (await m.authenticateBiometric()).valueOrNull!;
      expect(r, isA<AuthSuccess>());
      expect(bio.calls, <String>['check', 'prompt']);
    });

    test(
        'BB2 invalidated key: off (persisted), key deleted, no prompt, '
        'not counted', () async {
      final DefaultCredentialManager m = await enabledManager();
      bio.state = BiometricKeyState.invalidated;
      final AuthAttemptResult r =
          (await m.authenticateBiometric()).valueOrNull!;
      expect(r, isA<AuthFailure>());
      expect((r as AuthFailure).reason, AuthFailureReason.notConfigured);
      expect(bio.calls, isNot(contains('prompt')));
      expect(bio.calls, contains('delete'));
      expect(await storedOptions(), isNull);
      expect(await storedFailures(), 0);
      // Stays off for a new process (persisted), still no prompt.
      final AuthAttemptResult again =
          (await manager().authenticateBiometric()).valueOrNull!;
      expect((again as AuthFailure).reason, AuthFailureReason.notConfigured);
      expect(bio.calls.where((String c) => c == 'prompt'), isEmpty);
    });

    test('BB3 missing key (legacy, D3-b) is treated like invalidated',
        () async {
      final DefaultCredentialManager m = await enabledManager();
      bio.state = BiometricKeyState.missing;
      final AuthAttemptResult r =
          (await m.authenticateBiometric()).valueOrNull!;
      expect((r as AuthFailure).reason, AuthFailureReason.notConfigured);
      expect(bio.calls, isNot(contains('prompt')));
      expect(await storedOptions(), isNull);
      expect(await storedFailures(), 0);
    });

    test('BB4 keystore error: unavailable now, nothing changed', () async {
      final DefaultCredentialManager m = await enabledManager();
      bio.state = BiometricKeyState.error;
      final AuthAttemptResult r =
          (await m.authenticateBiometric()).valueOrNull!;
      expect((r as AuthFailure).reason, AuthFailureReason.notAvailable);
      expect(bio.calls, isNot(contains('prompt')));
      expect(bio.calls, isNot(contains('delete')));
      expect(await storedOptions(), isNotNull);
      expect(await storedFailures(), 0);
    });

    test('BB5 key invalidated at prompt time: off, not counted', () async {
      final DefaultCredentialManager m = await enabledManager();
      bio.promptResult = Result.failure(
          bindingError(BiometricAuthException.keyInvalidatedCode));
      final AuthAttemptResult r =
          (await m.authenticateBiometric()).valueOrNull!;
      expect((r as AuthFailure).reason, AuthFailureReason.notConfigured);
      expect(bio.calls, contains('delete'));
      expect(await storedOptions(), isNull);
      expect(await storedFailures(), 0);
    });
  });

  group('F18-3 enablement', () {
    test(
        'BB6 key created after verification and before saving; no key = '
        'not enabled', () async {
      final DefaultCredentialManager m = manager();
      await m.enrollPin(_pin);
      final List<String> order = <String>[];
      Future<BiometricOptions?>? optionsAtCreate;
      bio.onCreate = () {
        order.add('create');
        optionsAtCreate = storedOptions();
      };
      Future<BiometricEnableOutcome> enable() => enableBiometricUnlock(
            auth: m,
            service: bio,
            verifyPrimary: () async {
              order.add('verify');
              return AuthType.pin;
            },
            stillActive: () => true,
            now: () => now,
          );
      // Refused key: nothing saved.
      bio.createResult = false;
      expect(await enable(), BiometricEnableOutcome.unsupported);
      expect(await storedOptions(), isNull);
      expect(order, <String>['verify', 'create']);
      // Accepted key: the options are saved only after it exists.
      order.clear();
      bio.createResult = true;
      expect(await enable(), BiometricEnableOutcome.enabled);
      expect(order, <String>['verify', 'create']);
      expect(await optionsAtCreate, isNull);
      final BiometricOptions? saved = await storedOptions();
      expect(saved, isNotNull);
      expect(saved!.allowDeviceCredential, isFalse);
    });

    test('BB7 re-enabling after a change needs the app PIN/pattern', () async {
      final DefaultCredentialManager m = await enabledManager();
      bio.state = BiometricKeyState.invalidated;
      await m.authenticateBiometric(); // turned off
      bio.calls.clear();
      final BiometricEnableOutcome refused = await enableBiometricUnlock(
        auth: m,
        service: bio,
        verifyPrimary: () async => null, // PIN/pattern not verified
        stillActive: () => true,
        now: () => now,
      );
      expect(refused, BiometricEnableOutcome.notVerified);
      expect(bio.calls, isNot(contains('create')));
      expect(await storedOptions(), isNull);
      final BiometricEnableOutcome ok = await enableBiometricUnlock(
        auth: m,
        service: bio,
        verifyPrimary: () async => AuthType.pin,
        stillActive: () => true,
        now: () => now,
      );
      expect(ok, BiometricEnableOutcome.enabled);
      expect(bio.calls, contains('create'));
      expect((await m.authenticateBiometric()).valueOrNull, isA<AuthSuccess>());
    });
  });

  group('F18-3 platform contract', () {
    test('BB8 Dart bridge: exact arguments, code mapping, fail closed',
        () async {
      const MethodChannel ch =
          MethodChannel(KeyBoundBiometricService.channelName);
      final TestDefaultBinaryMessenger m =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      final KeyBoundBiometricService s = KeyBoundBiometricService(
        capabilities: bio,
      );
      // No native handler: fail closed everywhere.
      expect(await s.checkKey(), BiometricKeyState.error);
      expect(await s.createKey(), isFalse);
      final Result<bool> none = await s.authenticate(reason: 'r');
      expect(
          (none.errorOrNull! as BiometricAuthException).code, 'uiUnavailable');

      final List<MethodCall> seen = <MethodCall>[];
      Object? Function(MethodCall) reply = (MethodCall c) => true;
      m.setMockMethodCallHandler(ch, (MethodCall c) async {
        seen.add(c);
        return reply(c);
      });
      expect(
          (await s.authenticate(reason: 'Unlock', options: _enabled))
              .valueOrNull,
          isTrue);
      expect(seen.single.method, 'authenticate');
      expect(seen.single.arguments, <String, Object?>{
        'reason': 'Unlock',
        'requireConfirmation': true,
      });
      reply = (MethodCall c) => false; // no confirmation = failure
      expect((await s.authenticate(reason: 'r')).isFailure, isTrue);
      reply = (MethodCall c) => throw PlatformException(
          code: BiometricAuthException.keyInvalidatedCode);
      final BiometricAuthException e = (await s.authenticate(reason: 'r'))
          .errorOrNull! as BiometricAuthException;
      expect(e.code, BiometricAuthException.keyInvalidatedCode);
      expect(e.isCancellation || e.isAvailabilityError, isFalse);
      reply = (MethodCall c) => throw PlatformException(code: 'userCanceled');
      expect(
          ((await s.authenticate(reason: 'r')).errorOrNull!
                  as BiometricAuthException)
              .isCancellation,
          isTrue);
      reply = (MethodCall c) =>
          throw PlatformException(code: 'weird', message: 'platform text');
      final BiometricAuthException u = (await s.authenticate(reason: 'r'))
          .errorOrNull! as BiometricAuthException;
      expect(u.code, 'unknown');
      expect(u.message, isNot(contains('platform text')));
      for (final (String wire, BiometricKeyState want)
          in <(String, BiometricKeyState)>[
        ('valid', BiometricKeyState.valid),
        ('invalidated', BiometricKeyState.invalidated),
        ('missing', BiometricKeyState.missing),
        ('bogus', BiometricKeyState.error),
      ]) {
        reply = (MethodCall c) => wire;
        expect(await s.checkKey(), want);
      }
      reply = (MethodCall c) => true;
      expect(await s.createKey(), isTrue);
      m.setMockMethodCallHandler(ch, null);
    });

    test(
        'BB9 native contract: STRONG + CryptoObject only, invalidated by '
        'enrollment, success needs cipher output', () {
      const String dir = 'android/app/src/main/kotlin/com/smartapplock/app';
      final String ch = File('$dir/BiometricBindingChannel.kt')
          .readAsStringSync()
          .replaceAll(RegExp(r'//[^\n]*'), '');
      final String code = ch.replaceAll(RegExp(r'/\*[\s\S]*?\*/'), '');
      expect(
          RegExp(r'\.setAllowedAuthenticators\(BiometricManager\.Authenticators\.BIOMETRIC_STRONG\)')
              .allMatches(code)
              .length,
          1);
      expect(code, isNot(contains('BIOMETRIC_WEAK')));
      expect(code, isNot(contains('DEVICE_CREDENTIAL')));
      expect(code, isNot(contains('setDeviceCredentialAllowed')));
      expect(code, contains('.setInvalidatedByBiometricEnrollment(true)'));
      expect(
          code, isNot(contains('setInvalidatedByBiometricEnrollment(false)')));
      expect(code, contains('.setUserAuthenticationRequired(true)'));
      expect(code, contains('KeyProperties.AUTH_BIOMETRIC_STRONG)'));
      expect(code, contains('BiometricPrompt.CryptoObject(cipher)'));
      expect(
          RegExp(r'if \(BiometricBindingPolicy\.successConfirmed\(bytes\)\) \{\s*result\.success\(true\)')
              .hasMatch(code),
          isTrue);
      expect(RegExp(r'result\.success\(true\)').allMatches(code).length, 1);
      expect(code, contains('BiometricBindingPolicy.CODE_KEY_INVALIDATED'));
      // RL-01: no logging in the channel.
      expect(code, isNot(matches(RegExp(r'\bLog\.|println|printStackTrace'))));
    });

    test('BB10 production wiring', () {
      final String container =
          File('lib/app/app_container.dart').readAsStringSync();
      expect(container, contains('?? KeyBoundBiometricService()'));
      final String main = File(
              'android/app/src/main/kotlin/com/smartapplock/app/MainActivity.kt')
          .readAsStringSync();
      expect(main,
          contains('BiometricBindingChannel.register(flutterEngine, this)'));
      expect(main,
          contains('MonotonicClockChannel.register(flutterEngine, this)'));
      final String security =
          File('lib/ui/screens/security/security_screen.dart')
              .readAsStringSync();
      expect(security, contains('(service as BiometricBinding).deleteKey()'));
    });
  });
}
