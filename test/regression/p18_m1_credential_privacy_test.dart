// Phase 18 / M1 — raw credentials are never stored, logged or returned.
//
// SIMULATED (evidence B): the production DefaultCredentialManager over the
// production SecuritySettingsRepositoryImpl WITHOUT the settings cipher (so
// the persisted document is readable plaintext JSON and a raw credential
// would be visible), an in-memory database whose every settings row is
// snapshotted after EACH operation (no fake overriding setSetting, so the
// P13 CAS-G2 inventory is unchanged), deterministic salts (seeded Random, so the derived digests are
// fixed and the canary scan cannot be flaky), and an injected clock.
//
//  CP1 PIN lifecycle (enroll, wrong x3 -> lockout, process recreation,
//      correct after expiry, CR-3 verified change): the raw PIN and
//      the new PIN never appear in any written row or any returned result /
//      error text.
//  CP2 Pattern lifecycle: the raw node sequence never appears in any form.
//  CP3 Debug output: no raw credential is printed during the lifecycle.
import 'dart:async';
import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/repositories/impl/security_settings_repository_impl.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/credential_change_authorization.dart';
import 'package:smart_app_lock/security/credentials/credential_state_machine.dart';
import 'package:smart_app_lock/security/credentials/impl/default_credential_manager.dart';
import 'package:smart_app_lock/security/credentials/pattern_hasher.dart';
import 'package:smart_app_lock/security/pin_hasher.dart';
import 'package:smart_app_lock/utilities/result.dart';

const String _pin = '739154';
const String _newPin = '582607';
const List<int> _pattern = <int>[1, 5, 9, 6, 3, 2];

void main() {
  late InMemoryLocalDatabase db;
  final List<String> written = <String>[];
  late SecuritySettingsRepositoryImpl repo;
  late DateTime now;
  final List<String> returned = <String>[];
  final List<String> printed = <String>[];

  DefaultCredentialManager process() => DefaultCredentialManager(
        settings: repo,
        pinHasher: Pbkdf2PinHasher(iterations: 200, random: Random(18)),
        patternHasher: Pbkdf2PatternHasher(iterations: 200, random: Random(81)),
        stateMachine: CredentialStateMachine(
          maxFailedAttempts: 3,
          lockoutDuration: const Duration(seconds: 30),
        ),
        now: () => now,
      );

  /// Awaits one operation, records its result / error text and snapshots
  /// every settings row it may have written.
  Future<T> keep<T>(Future<Result<T>> f) async {
    final Result<T> r = await f;
    returned.add('${r.valueOrNull}');
    returned.add('${r.errorOrNull}');
    (await db.getAllSettings())
        .forEach((String k, String v) => written.add('$k=$v'));
    return r.valueOrNull as T;
  }

  setUp(() {
    db = InMemoryLocalDatabase();
    written.clear();
    repo = SecuritySettingsRepositoryImpl(db);
    now = DateTime(2026, 10, 22, 9);
    returned.clear();
    printed.clear();
  });

  Future<void> captured(Future<void> Function() body) => runZoned(
        body,
        zoneSpecification: ZoneSpecification(
          print: (Zone self, ZoneDelegate parent, Zone zone, String line) {
            printed.add(line);
            parent.print(zone, line);
          },
        ),
      );

  void expectAbsent(Iterable<String> haystack, List<String> canaries) {
    for (final String h in haystack) {
      for (final String c in canaries) {
        expect(h.contains(c), isFalse, reason: 'canary "$c" in: $h');
      }
    }
  }

  test('CP1 PIN lifecycle never stores, returns or prints the raw PIN',
      () async {
    await captured(() async {
      DefaultCredentialManager m = process();
      await keep(m.enrollPin(_pin));
      for (int i = 0; i < 3; i++) {
        await keep(m.authenticatePin('000000'));
      }
      final AuthAttemptResult locked = await keep(m.authenticatePin(_pin));
      expect(locked, isA<AuthLockedOut>());
      // Process recreation during the lockout.
      m = process();
      expect(await keep(m.authenticatePin(_pin)), isA<AuthLockedOut>());
      now = now.add(const Duration(seconds: 31));
      expect(await keep(m.authenticatePin(_pin)), isA<AuthSuccess>());
      // Verified change to a new PIN (CR-3 authorization).
      final CredentialChangeAttempt attempt =
          await keep(m.verifyPinForCredentialChange(_pin));
      expect(attempt.authorization, isNotNull);
      final Result<void> changed =
          await m.enrollPin(_newPin, authorization: attempt.authorization);
      returned.add('${changed.errorOrNull}');
      expect(changed.isSuccess, isTrue);
      // A wrong old PIN never issues an authorization.
      final CredentialChangeAttempt refused =
          await keep(m.verifyPinForCredentialChange(_pin));
      expect(refused.authorization, isNull);
      expect(await keep(m.authenticatePin(_newPin)), isA<AuthSuccess>());
      expect(await keep(m.status()), isNotNull);
    });
    expect(written, isNotEmpty);
    expectAbsent(written, <String>[_pin, _newPin]);
    expectAbsent((await db.getAllSettings()).values, <String>[_pin, _newPin]);
    expectAbsent(returned, <String>[_pin, _newPin]);
    expectAbsent(printed, <String>[_pin, _newPin]);
  });

  test('CP2 pattern lifecycle never stores, returns or prints the nodes',
      () async {
    final List<String> forms = <String>[
      _pattern.join(),
      _pattern.join(','),
      _pattern.join(', '),
      _pattern.toString(),
    ];
    await captured(() async {
      DefaultCredentialManager m = process();
      await keep(m.enrollPattern(_pattern));
      for (int i = 0; i < 3; i++) {
        await keep(m.authenticatePattern(const <int>[7, 8, 9, 6]));
      }
      expect(await keep(m.authenticatePattern(_pattern)), isA<AuthLockedOut>());
      m = process();
      now = now.add(const Duration(seconds: 31));
      expect(await keep(m.authenticatePattern(_pattern)), isA<AuthSuccess>());
      returned
          .add('${await keep(m.verifyPatternForCredentialChange(_pattern))}');
    });
    expect(written, isNotEmpty);
    expectAbsent(written, forms);
    expectAbsent((await db.getAllSettings()).values, forms);
    expectAbsent(returned, forms);
    expectAbsent(printed, forms);
  });
}
