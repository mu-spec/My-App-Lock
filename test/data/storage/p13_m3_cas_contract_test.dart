// P13/M3 F-1 — compareAndSetSetting contract for InMemoryLocalDatabase plus
// the static scope guards (no monitor / credential integration; the CAS is
// never routed around a test fake silently).
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/data/storage/local_database.dart';

const String k = 'security_settings';

void main() {
  group('CAS-M in-memory contract', () {
    test('CAS-M1 insert-if-absent / update / conflict / missing', () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      expect(await db.compareAndSetSetting(k, expected: 'A', next: 'B'),
          CasOutcome.conflict);
      expect(await db.getSetting(k), isNull);
      expect(await db.compareAndSetSetting(k, expected: null, next: 'A'),
          CasOutcome.committed);
      expect(await db.compareAndSetSetting(k, expected: null, next: 'Z'),
          CasOutcome.conflict);
      expect(await db.compareAndSetSetting(k, expected: 'A', next: 'B'),
          CasOutcome.committed);
      expect(await db.compareAndSetSetting(k, expected: 'A', next: 'C'),
          CasOutcome.conflict);
      expect(await db.getSetting(k), 'B');
    });

    test('CAS-M2 next == expected rejected without echoing the value',
        () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      await db.setSetting(k, 'S3CR3T');
      await expectLater(
          db.compareAndSetSetting(k, expected: 'S3CR3T', next: 'S3CR3T'),
          throwsA(isA<ArgumentError>().having((ArgumentError e) => '$e',
              'text', isNot(contains('S3CR3T')))));
      expect(await db.getSetting(k), 'S3CR3T');
    });

    test('CAS-M3 N concurrent CAS from one snapshot: exactly one commits',
        () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      await db.setSetting(k, 'v0');
      final List<CasOutcome> r = await Future.wait(<Future<CasOutcome>>[
        for (int i = 0; i < 16; i++)
          db.compareAndSetSetting(k, expected: 'v0', next: 'v1-$i'),
      ]);
      expect(r.where((CasOutcome o) => o == CasOutcome.committed), hasLength(1));
      expect(r.where((CasOutcome o) => o == CasOutcome.conflict), hasLength(15));
    });

    test('CAS-M4 interleaved increment loops lose nothing', () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      Future<void> worker(String w) async {
        for (int i = 0; i < 100; i++) {
          while (true) {
            final String? cur = await db.getSetting(k);
            final int n = cur == null ? 0 : int.parse(cur.split('|').first);
            await Future<void>.delayed(Duration.zero); // force interleaving
            if (await db.compareAndSetSetting(k,
                    expected: cur, next: '${n + 1}|$w#$i') ==
                CasOutcome.committed) {
              break;
            }
          }
        }
      }

      await Future.wait(<Future<void>>[for (int w = 0; w < 4; w++) worker('w$w')]);
      expect(int.parse((await db.getSetting(k))!.split('|').first), 400);
    });

    test('CAS-M5 reconcile: confirmed / notConfirmed / unreadable', () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      await db.setSetting(k, 'N');
      expect(await reconcileCompareAndSet(db, k, 'N'),
          CasReconciliation.confirmedCommitted);
      expect(await reconcileCompareAndSet(db, k, 'other'),
          CasReconciliation.notConfirmed);
      expect(await reconcileCompareAndSet(_UnreadableDb(), k, 'N'),
          CasReconciliation.unreadable);
    });

    test('CAS-M6 CasUnknownOutcome text is a fixed code only', () {
      for (final CasUnknownCode c in CasUnknownCode.values) {
        expect('${CasUnknownOutcome(c)}', 'CasUnknownOutcome(${c.name})');
      }
    });
  });

  group('CAS-G scope guards (static)', () {
    List<File> dartFiles(String root) => Directory(root)
        .listSync(recursive: true)
        .whereType<File>()
        .where((File f) => f.path.endsWith('.dart'))
        .toList();

    test('CAS-G1 no production caller outside lib/data/storage (no monitor '
        'or credential integration in this patch)', () {
      final List<String> callers = <String>[
        for (final File f in dartFiles('lib'))
          if (!f.path.replaceAll(r'\', '/').startsWith('lib/data/storage/') &&
              f.readAsStringSync().contains('compareAndSetSetting'))
            f.path,
      ];
      expect(callers, isEmpty);
    });

    test('CAS-G2 anti-vacuity: every test fake overriding setSetting is '
        'inventoried; none may inherit CAS once a caller exists', () {
      // A fake that overrides setSetting (fault injection, counters, delays)
      // INHERITS the atomic in-memory CAS, which would bypass that override.
      // Today that is harmless ONLY because CAS-G1 proves there is no
      // production caller. This test freezes the inventory so that a
      // future integration patch cannot silently route around a fake: any
      // change to the set (or any CAS caller appearing) fails here and
      // forces each listed fake to override compareAndSetSetting.
      final RegExp setOverride = RegExp(r'Future<void>\s+setSetting\(');
      final List<String> fakes = <String>[];
      int overrides = 0;
      int casOverrides = 0;
      for (final File f in dartFiles('test')) {
        final String src = f.readAsStringSync();
        final int n = setOverride.allMatches(src).length;
        if (n > 0 && src.contains('extends InMemoryLocalDatabase')) {
          fakes.add(f.path.replaceAll(r'\', '/'));
          overrides += n;
        }
        if (src.contains('Future<CasOutcome> compareAndSetSetting(') &&
            !f.path.contains('p13_m3_cas_')) {
          casOverrides++;
        }
      }
      expect(overrides, kSetSettingOverrides,
          reason: 'inventory changed: review CAS bypass for ${fakes.length} '
              'files');
      expect(fakes.length, kFakeFiles);
      expect(casOverrides, 0,
          reason: 'a fake now overrides CAS: update this inventory');
    });
  });
}

/// Frozen at 6110ff8 + this patch (see C/B evidence README).
const int kSetSettingOverrides = 42;
const int kFakeFiles = 38;

class _UnreadableDb extends InMemoryLocalDatabase {
  @override
  Future<String?> getSetting(String key) async =>
      throw StateError('unreadable');
}
