// Phase 18 / M1F — F18-9: the FK-S* reproducers no longer depend on the
// real date. SIMULATED (evidence B) + STATIC (evidence C).
//
//  DC1  root cause, pinned deterministically: the PRODUCTION 30-day age
//       retention prunes the fixed-date records when the monitor clock is
//       31 days later, and keeps them a few minutes later (retention is
//       unchanged; only the test clock was the problem).
//  DC2  every IntruderMonitor in the FK-S* file runs on the injected fixed
//       clock (none falls back to the real clock).
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/auth_result.dart';
import 'package:smart_app_lock/security/credentials/auth_type.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_monitor.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';

final DateTime _verdict = DateTime(2026, 10, 22, 12);

VerifiedAttempt _fail(String vid) => VerifiedAttempt(
      verificationId: vid,
      type: AuthType.pin,
      matched: false,
      result: const AuthFailure(
        reason: AuthFailureReason.wrongCredential,
        remainingAttempts: 2,
      ),
      counterPersisted: true,
      lockoutStreak: 0,
      context: AuthAttemptContext.smartAppLock,
      at: _verdict,
    );

Future<List<String>> _storedAfterSeeding(DateTime monitorNow) async {
  final InMemoryLocalDatabase db = InMemoryLocalDatabase();
  final InMemorySecretStore secrets = InMemorySecretStore();
  final IntruderFailureLogStore store = IntruderFailureLogStore(
    db,
    cipher: AesGcmSettingsCipher(secrets, database: db),
  );
  final IntruderMonitor m =
      IntruderMonitor(store: store, now: () => monitorNow);
  m.onVerifiedAttempt(_fail('a'));
  m.onVerifiedAttempt(_fail('b'));
  await m.idle();
  final IntruderLogRead r = await store.read();
  return r is IntruderLogLoaded
      ? r.log.events.map((e) => e.verificationId).toList()
      : <String>[];
}

void main() {
  test('DC1 production retention prunes 31-day-old records, keeps fresh ones',
      () async {
    expect(IntruderMonitor.defaultRetention, const Duration(days: 30));
    expect(
      await _storedAfterSeeding(_verdict.add(const Duration(minutes: 5))),
      <String>['a', 'b'],
    );
    expect(
      await _storedAfterSeeding(_verdict.add(const Duration(days: 31))),
      isEmpty,
    );
  });

  test('DC2 every monitor in the FK-S* reproducers uses the fixed clock', () {
    final String src = File(
      'test/security/encryption/'
      'p13_m3_f_key_1_store_destruction_reproducer_test.dart',
    ).readAsStringSync();
    final int monitors = 'IntruderMonitor('.allMatches(src).length;
    expect(monitors, 7);
    expect(
      RegExp(r'IntruderMonitor\(\s*now: _fixedNow,').allMatches(src).length,
      monitors,
    );
    expect(src,
        contains('DateTime _fixedNow() => DateTime(2026, 10, 22, 12, 5);'));
    expect(src, isNot(contains('DateTime.now')));
  });
}
