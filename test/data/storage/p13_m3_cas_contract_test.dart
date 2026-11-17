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
          throwsA(isA<ArgumentError>().having(
              (ArgumentError e) => '$e', 'text', isNot(contains('S3CR3T')))));
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
      expect(
          r.where((CasOutcome o) => o == CasOutcome.committed), hasLength(1));
      expect(
          r.where((CasOutcome o) => o == CasOutcome.conflict), hasLength(15));
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

      await Future.wait(
          <Future<void>>[for (int w = 0; w < 4; w++) worker('w$w')]);
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

    // P13/M3 NF-NS-1 RE-BASELINE (E-B6, disclosed): the credential fix makes
    // the security-settings repository the ONE production caller. Any other
    // caller (monitor, journal, evidence, UI) still fails here.
    // P13/M3 Q-ENG-1 RE-BASELINE (R8 allow-list, disclosed): the failure-
    // log store is the owner-authorized second caller. The set is EXACT:
    // the monitor, journal, evidence store and UI still fail here.
    // P13/M3 Batch 2 RE-BASELINE (R8 allow-list, disclosed): the F-KEY-1
    // master-key resolver commits `sec.key_commit` (K-2+B-compat) with CAS;
    // it is the owner-authorized third caller. Still EXACT.
    test(
        'CAS-G1 the only production callers outside lib/data/storage are '
        'the security-settings repository, the failure-log store and the '
        'master-key resolver', () {
      final List<String> callers = <String>[
        for (final File f in dartFiles('lib'))
          if (!f.path.replaceAll(r'\', '/').startsWith('lib/data/storage/') &&
              f.readAsStringSync().contains('compareAndSetSetting'))
            f.path.replaceAll(r'\', '/'),
      ]..sort();
      expect(callers, kCasCallers);
    });

    test(
        'CAS-G2 anti-vacuity: every test fake overriding setSetting is '
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
      // NF-NS-1 RE-BASELINE (E-B6): now that a caller exists, every fake
      // that intercepts security_settings (or every key) overrides CAS with
      // the same interception; nothing else does.
      expect(casOverrides, kCasOverrideFiles.length,
          reason: 'CAS override set changed: update this inventory');
      for (final String path in kCasOverrideFiles) {
        expect(
          File(path).readAsStringSync(),
          contains('Future<CasOutcome> compareAndSetSetting('),
          reason: '$path intercepts security_settings writes but would '
              'inherit an un-intercepted CAS',
        );
      }
    });
  });
}

/// Frozen at 6110ff8 + F-1 (42 / 38), re-baselined for NF-NS-1 (E-B6):
/// +1 override in the new NF-NS-1 transition test's fault store.
/// Batch 4 (disclosed re-baseline): +1 override / +1 file, the Clear History
/// fault store, which also routes compareAndSetSetting through the same
/// interception (listed in kCasOverrideFiles).
const int kSetSettingOverrides = 44;
const int kFakeFiles = 40;

/// NF-NS-1: the one production compare-and-set caller (CAS-G1).
const String kOnlyCasCaller =
    'lib/data/repositories/impl/security_settings_repository_impl.dart';

/// Q-ENG-1 (R8): the exact production caller set (sorted).
const List<String> kCasCallers = <String>[
  kOnlyCasCaller,
  // Batch 2 (F-KEY-1, K-2+B-compat key commitment), disclosed re-baseline.
  'lib/security/encryption/master_key_resolver.dart',
  'lib/security/intruder/intruder_evidence_store.dart',
  'lib/security/intruder/intruder_failure_log_store.dart',
  // E-2 (owner-directed, disclosed re-baseline): journal row and evidence
  // index / blob rows are written compare-and-set (R-P13M3-T1).
  'lib/security/timeline/security_event_journal_store.dart',
];

/// NF-NS-1: fakes that intercept security_settings / all-key writes and
/// therefore route compareAndSetSetting through the same interception.
const List<String> kCasOverrideFiles = <String>[
  'test/regression/host_auth_binding_test.dart',
  'test/regression/late_pop_route_binding_test.dart',
  'test/regression/p13_m2_isolation_test.dart',
  'test/security/credentials/credential_manager_test.dart',
  'test/security/credentials/p13_m3_nf_ns_1_state_transitions_test.dart',
  'test/security/intruder/intruder_outcome_observer_test.dart',
  'test/security/timeline/security_timeline_m2_read_model_test.dart',
  'test/security/timeline/security_timeline_test.dart',
  'test/ui/security/security_recommendations_card_test.dart',
  'test/ui/security/security_score_card_test.dart',
  'test/ui/security_screen_test.dart',
  // Q-ENG-1 (contract A §6): fakes intercepting failure-log writes.
  'test/regression/p12_intruder_defense_m1_test.dart',
  'test/regression/p12_m2_final_gate_test.dart',
  'test/regression/p13_p1_monitor_reliability_test.dart',
  'test/security/credentials/auth_core_final_gate_test.dart',
  'test/security/intruder/intruder_defense_coordinator_test.dart',
  'test/security/intruder/intruder_monitor_p1_test.dart',
  'test/security/intruder/intruder_monitor_test.dart',
  'test/security/intruder/p13_m3_q_eng_1_monitor_cas_test.dart',
  'test/security/timeline/security_timeline_concurrency_test.dart',
  // Batch 2: resolver tests inject CAS unknown-outcome faults (KC-05).
  'test/security/encryption/p13_m3_b2_master_key_resolver_test.dart',
  // Batch 3 (B-D1 cond. 7, disclosed): process-death fault on the
  // failure-log CAS (the dying instance's CAS never returns).
  'test/security/intruder/p13_m3_b3_downgrade_test.dart',
  'test/security/intruder/p13_m3_b3_crash_concurrency_test.dart',
  'test/security/intruder/p13_m3_b3_identity_test.dart',
  // Batch 4: Clear History fault stores (failure-log CAS faults).
  'test/regression/p13_m3_b4_clear_history_ui_test.dart',
  'test/security/history/p13_m3_b4_clear_history_test.dart',
  // E-2: fakes intercepting journal / evidence writes (now compare-and-set).
  'test/regression/p12_m3_owner_lockout_qa_test.dart',
  'test/regression/p13_m1_security_timeline_test.dart',
  'test/security/intruder/intruder_evidence_management_m3_test.dart',
  'test/security/intruder/intruder_evidence_store_test.dart',
  'test/security/intruder/intruder_evidence_tombstone_compaction_m3_test.dart',
  'test/security/timeline/security_event_journal_test.dart',
  'test/security/timeline/security_journal_migration_test.dart',
  'test/security/timeline/security_journal_producers_test.dart',
];

class _UnreadableDb extends InMemoryLocalDatabase {
  @override
  Future<String?> getSetting(String key) async =>
      throw StateError('unreadable');
}
