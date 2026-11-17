// Phase 14 final verification — the structural credential-leak scan used by
// the Phase 12 "attempted PIN never appears in the stored log" test.
//  L-1 the old false positive (PIN digits inside a timestamp or random id) is
//      reproduced deterministically and no longer fails;
//  L-2 an intentionally leaked PIN is detected in every place it could hide
//      (new field, existing string, number, key, nested, each opaque field);
//  L-3 end to end on a real stored intruder log: clean = no finding; the
//      same log with an injected leak = finding.
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/intruder/log_generation.dart';

import '../support/credential_leak_scan.dart';

const String _pin = '9137';
const String _enrolled = '2580';
const List<String> _secrets = <String>[_pin, _enrolled];
const int _at = 1794913742731; // contains "9137" (the observed flake)

Map<String, OpaqueValidator> _opaque(DateTime from, DateTime to) =>
    <String, OpaqueValidator>{
      'gen': LogGeneration.isValid,
      'events[].vid': verificationId(_secrets),
      'events[].at': timestampWithin(from, to),
    };

final DateTime _from = DateTime.fromMillisecondsSinceEpoch(_at - 5000);
final DateTime _to = DateTime.fromMillisecondsSinceEpoch(_at + 5000);

Map<String, Object?> _cleanDoc() => <String, Object?>{
      'schema': 'sal.intruder_log',
      'v': 2,
      'gen': 'AAAA9137AAAA2580AAAAAA', // valid random-id shape, contains both
      'nextSeq': 1,
      'events': <Object?>[
        <String, Object?>{
          'seq': 0,
          'vid': '9137abcd2580ef01:1', // random nonce contains both
          'at': _at,
          'method': 'pin',
          'surface': 'protectedAppChallenge',
          'pkg': 'com.whatsapp',
          'gen': 1,
          'chal': 1,
          'run': 1,
          'lockout': false,
          'streak': 0,
          'persisted': true,
        },
      ],
    };

List<String> _scan(Map<String, Object?> doc) =>
    findCredentialLeaks(jsonEncode(doc), _secrets, opaque: _opaque(_from, _to));

Map<String, Object?> _event(Map<String, Object?> doc) =>
    (doc['events']! as List<Object?>).single! as Map<String, Object?>;

void main() {
  test(
      'L-1 the old false positive: digits inside the timestamp and random ids '
      'are not a leak (the old whole-text check would have failed)', () {
    final Map<String, Object?> doc = _cleanDoc();
    expect(jsonEncode(doc), contains(_pin),
        reason: 'old check: false positive');
    expect(jsonEncode(doc), contains(_enrolled));
    expect(_scan(doc), isEmpty);
    expect(LogGeneration.isValid(doc['gen']), isTrue);
  });

  final Map<String, void Function(Map<String, Object?>)> leaks =
      <String, void Function(Map<String, Object?>)>{
    'new top-level field': (Map<String, Object?> d) => d['pin'] = _pin,
    'inside an existing string': (Map<String, Object?> d) =>
        _event(d)['method'] = 'pin:$_pin',
    'the enrolled PIN in the package field': (Map<String, Object?> d) =>
        _event(d)['pkg'] = 'com.x$_enrolled',
    'as a number': (Map<String, Object?> d) => _event(d)['attempt'] = 9137,
    'inside a larger number': (Map<String, Object?> d) =>
        _event(d)['run'] = 1913700,
    'as a key': (Map<String, Object?> d) => d[_pin] = true,
    'nested in a list and map': (Map<String, Object?> d) =>
        _event(d)['extra'] = <Object?>[
          'x',
          <String, Object?>{'y': 'a${_pin}b'}
        ],
    'as the timestamp (outside the attempt window)': (Map<String, Object?> d) =>
        _event(d)['at'] = 9137,
    'inside a timestamp outside the window': (Map<String, Object?> d) =>
        _event(d)['at'] = 1794913700000,
    'timestamp as a string': (Map<String, Object?> d) =>
        _event(d)['at'] = '$_at',
    'in the verification counter': (Map<String, Object?> d) =>
        _event(d)['vid'] = '0123456789abcdef:9137',
    'replacing the verification nonce': (Map<String, Object?> d) =>
        _event(d)['vid'] = 'pin$_pin:1',
    'as the log generation': (Map<String, Object?> d) => d['gen'] = _pin,
    'appended to the log generation': (Map<String, Object?> d) =>
        d['gen'] = '${d['gen']}$_pin',
  };

  for (final MapEntry<String, void Function(Map<String, Object?>)> leak
      in leaks.entries) {
    test('L-2 an intentionally leaked PIN is detected: ${leak.key}', () {
      final Map<String, Object?> doc = _cleanDoc();
      leak.value(doc);
      expect(_scan(doc), isNotEmpty);
    });
  }

  test('L-2 a scan without secrets is refused (cannot pass vacuously)', () {
    expect(
        () => findCredentialLeaks('{}', const <String>[]), throwsArgumentError);
    expect(() => findCredentialLeaks('{}', const <String>['']),
        throwsArgumentError);
  });

  test('L-3 end to end on a real stored intruder log', () async {
    final InMemoryLocalDatabase db = InMemoryLocalDatabase();
    final AppContainer c = AppContainer.inMemory(database: db);
    await c.auth.enrollPin(_enrolled);
    final DateTime before = DateTime.now();
    await AuthAttemptContext.protectedAppChallenge(
      packageName: 'com.whatsapp',
      generation: 1,
      challengeSerial: 1,
    ).run(() => c.auth.authenticatePin(_pin));
    await c.intruderMonitor.idle();
    final DateTime after = DateTime.now();
    final String raw =
        (await db.getSetting(IntruderFailureLogStore.storageKey))!;
    final String plain = await c.settingsCipher.decryptString(raw.substring(7));
    final Map<String, Object?> doc = jsonDecode(plain) as Map<String, Object?>;
    expect(doc['events'], hasLength(1));
    expect(findCredentialLeaks(plain, _secrets, opaque: _opaque(before, after)),
        isEmpty);

    _event(doc)['note'] = 'typed $_pin';
    expect(
        findCredentialLeaks(jsonEncode(doc), _secrets,
            opaque: _opaque(before, after)),
        isNotEmpty);
  });
}
