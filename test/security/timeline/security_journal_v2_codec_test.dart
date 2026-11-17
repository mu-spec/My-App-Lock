// Phase 13 / M2 — T1: strict journal v2 codec (U-01…U-07, U-10b) and
// terminal-outcome family exclusivity at decode.
//
// SIMULATED: pure Dart VM, in-memory storage.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/protection_health_journal_recorder.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/protection/health/protection_health_engine.dart';
import 'package:smart_app_lock/security/encryption/settings_cipher_impl.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal_store.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';

const int _maxSafe = 0x1fffffffffffff;

Map<String, Object?> ev(int seq, String type,
        {Object? f, bool? cb, int at = 1000}) =>
    <String, Object?>{
      'seq': seq,
      'at': at,
      'type': type,
      if (f != null) 'f': f,
      if (cb != null) 'cb': cb,
    };

Map<String, Object?> doc2(List<Object?> events,
        {int? nextSeq,
        Map<String, Object?> extra = const <String, Object?>{}}) =>
    <String, Object?>{
      'schema': SecurityJournalDocument.schema,
      'v': 2,
      'nextSeq': nextSeq ?? events.length + 1,
      'discarded': 0,
      'lost': 0,
      ...extra,
      'events': events,
    };

SecurityJournalDocument decode(Map<String, Object?> raw) =>
    SecurityJournalDocument.fromJson(jsonDecode(jsonEncode(raw)));

/// One valid event of every type, with its exact `f`.
final Map<String, Object?> validF = <String, Object?>{
  'journalStarted': null,
  'journalRecovered': null,
  'journalUpgraded': <String, Object?>{'from': 1},
  'captureSaved': <String, Object?>{'trig': 7},
  'captureNotSaved': <String, Object?>{'trig': 8, 'why': 'camera'},
  'alarmStarted': <String, Object?>{'trig': 9},
  'alarmNotStarted': <String, Object?>{'trig': 10, 'why': 'dnd'},
  'alarmStopped': <String, Object?>{},
  'protectionHealth': <String, Object?>{
    's': 'attention',
    'c': <String>['overlayUnavailable'],
    'first': true,
    'sup': 2,
  },
  'storageUnavailable': <String, Object?>{
    'src': 'failureLog',
    'kind': 'failing'
  },
  'storageRestored': <String, Object?>{'src': 'failureLog'},
};

Map<String, Object?> docWith(String type, Object? f, {bool? cb}) => doc2(
      <Object?>[ev(0, 'journalStarted'), ev(1, type, f: f, cb: cb)],
      extra: type == 'journalUpgraded'
          ? const <String, Object?>{'from': 1}
          : const <String, Object?>{},
    );

void main() {
  group('U-01 round trip + deterministic encode', () {
    test('every type round-trips byte-identically', () {
      final List<Object?> events = <Object?>[ev(0, 'journalStarted')];
      int seq = 1;
      validF.forEach((String type, Object? f) {
        if (type == 'journalStarted') return;
        events.add(ev(seq++, type,
            f: f, cb: type.startsWith('journal') ? null : true));
      });
      final Map<String, Object?> raw = doc2(events, extra: <String, Object?>{
        'from': 1,
        'hs': <String, Object?>{
          's': 'offline',
          'c': <String>['detectionOffline', 'overlayUnavailable'],
          'at': 5,
        },
        'ss': <String, Object?>{'failureLog': 'failing'},
        'sup': 3,
      });
      final SecurityJournalDocument d = decode(raw);
      expect(d.events.length, validF.length);
      expect(jsonEncode(d.toJson()), jsonEncode(raw));
      expect(jsonEncode(decode(d.toJson()).toJson()), jsonEncode(raw));
    });

    test('codes are sorted and de-duplicated on encode; zero fields omitted',
        () {
      final ProtectionHealthFields f = ProtectionHealthFields(
        state: HState.offline,
        codes: <HCode>[
          HCode.watcherNotRunning,
          HCode.detectionOffline,
          HCode.watcherNotRunning
        ],
        first: false,
      );
      expect(jsonEncode(f.toJson()),
          '{"s":"offline","c":["detectionOffline","watcherNotRunning"],"first":false}');
      const SecurityJournalDocument d = SecurityJournalDocument(
          nextSeq: 0, discarded: 0, lost: 0, events: <SecurityJournalEvent>[]);
      expect(jsonEncode(d.toJson()),
          '{"schema":"sal.security_journal","v":2,"nextSeq":0,"discarded":0,"lost":0,"events":[]}');
    });
  });

  group('U-02 f required / forbidden / exact key set (E-2)', () {
    for (final MapEntry<String, Object?> e in validF.entries) {
      test('${e.key}: valid f decodes', () {
        expect(decode(docWith(e.key, e.value)).events.last.type.name, e.key);
      });
      if (e.value == null) {
        test('${e.key}: any f ⇒ corrupt', () {
          expect(() => decode(docWith(e.key, <String, Object?>{})),
              throwsFormatException);
        });
      } else {
        test('${e.key}: missing f / extra key / missing key ⇒ corrupt', () {
          final Map<String, Object?> raw = docWith(e.key, null);
          expect(() => decode(raw), throwsFormatException);
          final Map<String, Object?> extra = <String, Object?>{
            ...(e.value! as Map<String, Object?>),
            'zzz': 1,
          };
          expect(() => decode(docWith(e.key, extra)), throwsFormatException);
          final Map<String, Object?> m = e.value! as Map<String, Object?>;
          for (final String k in m.keys) {
            if (k == 'sup') continue; // optional
            final Map<String, Object?> less = Map<String, Object?>.of(m)
              ..remove(k);
            expect(() => decode(docWith(e.key, less)), throwsFormatException,
                reason: 'missing $k');
          }
        });
      }
    }
  });

  group('U-03 enums, ranges and code lists (E-3, J-6)', () {
    test('unknown enum wire value in every enum field ⇒ corrupt', () {
      final List<(String, Map<String, Object?>)> bad =
          <(String, Map<String, Object?>)>[
        ('captureNotSaved', <String, Object?>{'trig': 1, 'why': 'nope'}),
        ('alarmNotStarted', <String, Object?>{'trig': 1, 'why': 'nope'}),
        (
          'protectionHealth',
          <String, Object?>{'s': 'nope', 'c': <String>[], 'first': false}
        ),
        (
          'protectionHealth',
          <String, Object?>{
            's': 'secure',
            'c': <String>['batterySaverOn'],
            'first': false
          }
        ),
        (
          'storageUnavailable',
          <String, Object?>{'src': 'x', 'kind': 'failing'}
        ),
        (
          'storageUnavailable',
          <String, Object?>{'src': 'failureLog', 'kind': 'ok'}
        ),
        ('storageRestored', <String, Object?>{'src': 'evidence'}),
      ];
      for (final (String t, Map<String, Object?> f) in bad) {
        expect(() => decode(docWith(t, f)), throwsFormatException,
            reason: '$t $f');
      }
    });

    test('trig range and type', () {
      for (final Object v in <Object>[-1, _maxSafe + 1, 1.5, '3']) {
        expect(
            () => decode(docWith('captureSaved', <String, Object?>{'trig': v})),
            throwsFormatException,
            reason: 'trig $v');
      }
      expect(
          decode(docWith('captureSaved', <String, Object?>{'trig': _maxSafe}))
              .events
              .last
              .fields!
              .trig,
          _maxSafe);
    });

    test('sup < 0; codes unsorted / duplicate / unknown / > 13 ⇒ corrupt', () {
      Map<String, Object?> h(Object c, {Object sup = 0}) => <String, Object?>{
            's': 'attention',
            'c': c,
            'first': false,
            'sup': sup,
          };
      expect(() => decode(docWith('protectionHealth', h(<String>[], sup: -1))),
          throwsFormatException);
      expect(
          () => decode(docWith('protectionHealth',
              h(<String>['overlayUnavailable', 'detectionOffline']))),
          throwsFormatException);
      expect(
          () => decode(docWith('protectionHealth',
              h(<String>['detectionOffline', 'detectionOffline']))),
          throwsFormatException);
      expect(() => decode(docWith('protectionHealth', h(<String>['zzz']))),
          throwsFormatException);
      final List<String> all = HCode.values.map((HCode c) => c.name).toList()
        ..sort();
      expect(decode(docWith('protectionHealth', h(all))).events.last.type,
          SecurityJournalEventType.protectionHealth);
      expect(
          () =>
              decode(docWith('protectionHealth', h(<String>[...all, 'zzzz']))),
          throwsFormatException);
    });

    test('hs / ss shape (J-6, J-7)', () {
      Map<String, Object?> with_(Map<String, Object?> extra) =>
          doc2(<Object?>[ev(0, 'journalStarted')], extra: extra);
      expect(
          () => decode(with_(<String, Object?>{
                'hs': <String, Object?>{'s': 'secure', 'c': <String>[]}
              })),
          throwsFormatException);
      expect(
          () => decode(with_(<String, Object?>{
                'ss': <String, Object?>{'evidence': 'ok'}
              })),
          throwsFormatException);
      expect(
          () => decode(with_(<String, Object?>{
                'ss': <String, Object?>{'failureLog': 'gone'}
              })),
          throwsFormatException);
      expect(
          decode(with_(<String, Object?>{
            'ss': <String, Object?>{'failureLog': 'ok'}
          })).storage[StorageSource.failureLog],
          StoreState.ok);
    });
  });

  group('U-04 cb / from / journalUpgraded (E-4, E-6, J-5)', () {
    test('cb must be true and is forbidden on the three markers', () {
      expect(
          () => decode(
              docWith('captureSaved', <String, Object?>{'trig': 1}, cb: false)),
          throwsFormatException);
      expect(
          decode(docWith('captureSaved', <String, Object?>{'trig': 1},
                  cb: true))
              .events
              .last
              .clockBack,
          isTrue);
      for (final String m in <String>[
        'journalStarted',
        'journalRecovered',
        'journalUpgraded'
      ]) {
        expect(() => decode(docWith(m, validF[m], cb: true)),
            throwsFormatException,
            reason: m);
      }
    });

    test('from must be 1; journalUpgraded at most once and only with from', () {
      expect(
          () => decode(doc2(<Object?>[ev(0, 'journalStarted')],
              extra: const <String, Object?>{'from': 2})),
          throwsFormatException);
      expect(
          () => decode(doc2(<Object?>[
                ev(0, 'journalStarted'),
                ev(1, 'journalUpgraded', f: <String, Object?>{'from': 1}),
              ])),
          throwsFormatException,
          reason: 'upgrade marker without from');
      expect(
          () => decode(doc2(<Object?>[
                ev(0, 'journalStarted'),
                ev(1, 'journalUpgraded', f: <String, Object?>{'from': 1}),
                ev(2, 'journalUpgraded', f: <String, Object?>{'from': 1}),
              ], extra: const <String, Object?>{
                'from': 1
              })),
          throwsFormatException);
    });
  });

  group('E-5+ terminal-outcome exclusivity at decode', () {
    test('two outcomes of one family for one trigger ⇒ corrupt', () {
      for (final (String a, Object fa, String b, Object fb)
          in <(String, Object, String, Object)>[
        (
          'captureSaved',
          <String, Object?>{'trig': 4},
          'captureSaved',
          <String, Object?>{'trig': 4}
        ),
        (
          'captureSaved',
          <String, Object?>{'trig': 4},
          'captureNotSaved',
          <String, Object?>{'trig': 4, 'why': 'storage'}
        ),
        (
          'captureNotSaved',
          <String, Object?>{'trig': 4, 'why': 'busy'},
          'captureNotSaved',
          <String, Object?>{'trig': 4, 'why': 'camera'}
        ),
        (
          'alarmStarted',
          <String, Object?>{'trig': 4},
          'alarmNotStarted',
          <String, Object?>{'trig': 4, 'why': 'dnd'}
        ),
        (
          'alarmNotStarted',
          <String, Object?>{'trig': 4, 'why': 'dnd'},
          'alarmStarted',
          <String, Object?>{'trig': 4}
        ),
      ]) {
        expect(
            () => decode(doc2(<Object?>[
                  ev(0, 'journalStarted'),
                  ev(1, a, f: fa),
                  ev(2, b, f: fb),
                ])),
            throwsFormatException,
            reason: '$a + $b');
      }
    });

    test(
        'one capture AND one alarm outcome per trigger is valid; different '
        'triggers are independent', () {
      final SecurityJournalDocument d = decode(doc2(<Object?>[
        ev(0, 'journalStarted'),
        ev(1, 'captureSaved', f: <String, Object?>{'trig': 4}),
        ev(2, 'alarmStarted', f: <String, Object?>{'trig': 4}),
        ev(3, 'captureNotSaved',
            f: <String, Object?>{'trig': 5, 'why': 'busy'}),
        ev(4, 'alarmNotStarted',
            f: <String, Object?>{'trig': 5, 'why': 'alreadyPlaying'}),
        ev(5, 'alarmStopped', f: <String, Object?>{}),
        ev(6, 'alarmStopped', f: <String, Object?>{}),
      ]));
      expect(d.events.length, 7);
    });
  });

  group('U-05 v1 documents reject v2 content (J-8)', () {
    Map<String, Object?> doc1(List<Object?> events,
            {Map<String, Object?> extra = const <String, Object?>{}}) =>
        <String, Object?>{
          ...doc2(events, extra: extra),
          'v': 1,
        };
    test('v1 with only markers decodes (in-memory upgrade, from = 1)', () {
      final SecurityJournalDocument d = decode(doc1(<Object?>[
        ev(0, 'journalStarted'),
        ev(1, 'journalRecovered'),
      ]));
      expect(d.decodedVersion, 1);
      expect(d.from, 1);
      expect(d.needsUpgradeMarker, isTrue);
    });
    test('any v2-only type, f, cb, from, hs, ss or sup ⇒ corrupt', () {
      validF.forEach((String type, Object? f) {
        if (type == 'journalStarted' || type == 'journalRecovered') return;
        expect(
            () => decode(
                doc1(<Object?>[ev(0, 'journalStarted'), ev(1, type, f: f)])),
            throwsFormatException,
            reason: type);
      });
      expect(
          () => decode(doc1(<Object?>[
                ev(0, 'journalStarted', f: <String, Object?>{}),
              ])),
          throwsFormatException);
      expect(
          () => decode(doc1(<Object?>[
                ev(0, 'journalStarted'),
                ev(1, 'journalRecovered', cb: true),
              ])),
          throwsFormatException);
      for (final MapEntry<String, Object?> x in <String, Object?>{
        'from': 1,
        'hs': <String, Object?>{'s': 'secure', 'c': <String>[], 'at': 1},
        'ss': <String, Object?>{'failureLog': 'ok'},
        'sup': 1,
      }.entries) {
        expect(
            () => decode(doc1(<Object?>[ev(0, 'journalStarted')],
                extra: <String, Object?>{x.key: x.value})),
            throwsFormatException,
            reason: x.key);
      }
    });
  });

  group('U-06 freeze golden (version 2)', () {
    test('type names, f keys and enum wire names are frozen', () {
      expect(SecurityJournalDocument.version, 2);
      expect(
          SecurityJournalEventType.values
              .map((SecurityJournalEventType t) => t.name)
              .toList(),
          <String>[
            'journalStarted',
            'journalRecovered',
            'journalUpgraded',
            'captureSaved',
            'captureNotSaved',
            'alarmStarted',
            'alarmNotStarted',
            'alarmStopped',
            'protectionHealth',
            'storageUnavailable',
            'storageRestored',
          ]);
      expect(CaptureWhy.values.map((CaptureWhy e) => e.name).toList(), <String>[
        'permission',
        'camera',
        'timeout',
        'busy',
        'cancelled',
        'duplicate',
        'storage',
        'encryption',
        'image',
        'superseded',
        'unsupported',
        'error',
      ]);
      expect(AlarmWhy.values.map((AlarmWhy e) => e.name).toList(), <String>[
        'alreadyPlaying',
        'dnd',
        'ringer',
        'focusDenied',
        'notForeground',
        'cancelled',
        'error',
      ]);
      expect(HState.values.map((HState e) => e.name).toList(),
          <String>['secure', 'attention', 'offline']);
      expect(HCode.values.map((HCode e) => e.name).toSet(), <String>{
        'protectionNotConfigured',
        'enforcementNotArmed',
        'overlayUnavailable',
        'detectionOffline',
        'accessibilityUnavailable',
        'accessibilityNotRunning',
        'usageAccessUnavailable',
        'watcherNotRunning',
        'shieldNotArmed',
        'notificationsDisabled',
        'backgroundRestricted',
        'signalUnknown',
        'healthSnapshotStale',
      });
      expect(StoreKind.values.map((StoreKind e) => e.name).toList(),
          <String>['failing', 'readOnly']);
      expect(StoreState.values.map((StoreState e) => e.name).toList(),
          <String>['ok', 'failing', 'readOnly']);
      expect(StorageSource.values.map((StorageSource e) => e.name).toList(),
          <String>['failureLog']);
      final Map<String, Set<String>> keys = <String, Set<String>>{
        'journalUpgraded': <String>{'from'},
        'captureSaved': <String>{'trig'},
        'captureNotSaved': <String>{'trig', 'why'},
        'alarmStarted': <String>{'trig'},
        'alarmNotStarted': <String>{'trig', 'why'},
        'alarmStopped': <String>{},
        'protectionHealth': <String>{'s', 'c', 'first', 'sup'},
        'storageUnavailable': <String>{'src', 'kind'},
        'storageRestored': <String>{'src'},
      };
      keys.forEach((String t, Set<String> k) {
        expect((validF[t]! as Map<String, Object?>).keys.toSet(), k, reason: t);
      });
      expect(
          jsonEncode(const CaptureNotSavedFields(3, CaptureWhy.busy).toJson()),
          '{"trig":3,"why":"busy"}');
      expect(jsonEncode(const AlarmNotStartedFields(3, AlarmWhy.dnd).toJson()),
          '{"trig":3,"why":"dnd"}');
      expect(jsonEncode(const AlarmStoppedFields().toJson()), '{}');
      expect(jsonEncode(const JournalUpgradedFields().toJson()), '{"from":1}');
    });
  });

  group('U-07 HCode ↔ HealthIssueCode', () {
    test('exactly the 13 non-advisory codes map; advisory codes do not', () {
      final Set<HCode> mapped = <HCode>{};
      for (final HealthIssueCode c in HealthIssueCode.values) {
        final HCode? h = ProtectionHealthJournalRecorder.journalCode(c);
        if (c.severity == HealthIssueSeverity.advisory) {
          expect(h, isNull, reason: c.name);
        } else {
          expect(h, isNotNull, reason: c.name);
          expect(h!.name, c.name);
          mapped.add(h);
        }
      }
      expect(mapped, HCode.values.toSet());
      expect(HCode.values.length, 13);
    });
  });

  group('U-10b boundary pin (the M1 fixture at v == 2)', () {
    test(
        'the malformed M1 "newer" fixture declared v2 is CORRUPT and goes '
        'through quarantine first', () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      // Exactly the M1 fixture from security_event_journal_test.dart L329
      // with its original "v":2 token.
      const String fixture = '{"schema":"sal.security_journal","v":2,'
          '"nextSeq":9,"events":[{"seq":1,"futureField":true}]}';
      await db.setSetting(SecurityEventJournalStore.storageKey, fixture);
      final SecurityEventJournalStore store = SecurityEventJournalStore(db);
      expect(await store.read(), isA<SecurityJournalCorrupt>());
      final SecurityEventJournal j = SecurityEventJournal(
          store: store, now: () => DateTime(2026, 10, 22, 12));
      await j.startup();
      await j.idle();
      expect(await db.getSetting(SecurityEventJournalStore.quarantineKey),
          fixture);
      expect(j.quarantinedCorruptJournal, isTrue);
      expect(j.health, isNot(SecurityJournalHealth.readOnly));
    });

    test('v == 3 with the right schema is unsupported (never decoded)',
        () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final AesGcmSettingsCipher c = AesGcmSettingsCipher(InMemorySecretStore(),
          database: InMemoryLocalDatabase());
      final SecurityEventJournalStore store =
          SecurityEventJournalStore(db, cipher: null);
      await db.setSetting(SecurityEventJournalStore.storageKey,
          jsonEncode(<String, Object?>{...doc2(<Object?>[]), 'v': 3}));
      final SecurityJournalRead r = await store.read();
      expect(r, isA<SecurityJournalUnsupported>());
      expect((r as SecurityJournalUnsupported).version, 3);
      expect(c, isNotNull);
    });
  });
}
