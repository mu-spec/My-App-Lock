// Phase 13 / M2 — T9: isolation and integration (I-01…I-04, F-05, F-05b)
// and static source checks (S-01…S-06).
//
// SIMULATED: real container (AppContainer.inMemory), real credential
// manager / monitor / coordinator / stores, scripted platform. The UI half
// of I-02 and F-05b is covered by T7/T8 (keys); these tests pin the data
// path. Static checks read lib/ sources from the package root.

import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:smart_app_lock/app/app_container.dart';
import 'package:smart_app_lock/data/storage/impl/in_memory_local_database.dart';
import 'package:smart_app_lock/security/credentials/credential_state.dart';
import 'package:smart_app_lock/security/credentials/verified_attempt.dart';
import 'package:smart_app_lock/security/intruder/intruder_defense_coordinator.dart';
import 'package:smart_app_lock/security/intruder/intruder_defense_settings.dart';
import 'package:smart_app_lock/security/intruder/intruder_evidence_service.dart';
import 'package:smart_app_lock/security/intruder/intruder_evidence_store.dart';
import 'package:smart_app_lock/security/intruder/intruder_failure_log_store.dart';
import 'package:smart_app_lock/security/storage/impl/in_memory_secret_store.dart';
import 'package:smart_app_lock/security/storage/secret_store.dart';
import 'package:smart_app_lock/security/timeline/intruder_outcome_journal_adapter.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal.dart';
import 'package:smart_app_lock/security/timeline/security_event_journal_store.dart';
import 'package:smart_app_lock/security/timeline/security_journal_event.dart';
import 'package:smart_app_lock/security/timeline/security_timeline.dart';
import 'package:smart_app_lock/security/timeline/security_timeline_grouping.dart';

import '../support/intruder_fixtures.dart';

const String _pin = '482916';
const String _app = 'com.example.bank';
const String _jKey = SecurityEventJournalStore.storageKey;

class _ThrowingObserver implements IntruderOutcomeObserver {
  @override
  void onIntruderOutcome(IntruderOutcome o) => throw StateError('observer');
}

class _NoopObserver implements IntruderOutcomeObserver {
  @override
  void onIntruderOutcome(IntruderOutcome o) {}
}

class _BrokenJournalDb extends InMemoryLocalDatabase {
  @override
  Future<String?> getSetting(String key) async {
    if (key.startsWith(_jKey)) throw StateError('journal read');
    return super.getSetting(key);
  }

  @override
  Future<void> setSetting(String key, String value) async {
    if (key.startsWith(_jKey)) throw StateError('journal write');
    return super.setSetting(key, value);
  }
}

Future<AppContainer> _container({
  InMemoryLocalDatabase? db,
  SecretStore? secrets,
  GatedEvidenceService? platform,
}) async {
  final AppContainer c = AppContainer.inMemory(
    intruderEvidence: platform ??
        (GatedEvidenceService()..permission = CameraPermissionState.granted),
    database: db ?? InMemoryLocalDatabase(),
    secretStore: secrets,
  );
  await c.intruderStartup;
  await c.securityJournalStartup;
  return c;
}

Future<String?> _challenge(AppContainer c, String pin, int n) async {
  final dynamic r = await AuthAttemptContext.protectedAppChallenge(
    packageName: _app,
    generation: n,
    challengeSerial: n,
  ).run(() => c.auth.authenticatePin(pin));
  return r.toString().split('(').first;
}

String _status(IntruderDefenseStatus s) => <Object?>[
      s.triggers,
      s.captured,
      s.captureSkipped,
      s.captureFailed,
      s.captureCancelled,
      s.saveFailed,
      s.alarmsStarted,
      s.alarmsSuppressed,
      s.alarmsCancelled,
      s.errors,
      s.lastFailure,
    ].join('|');

String _src(String rel) => File(rel).readAsStringSync();

const List<String> _m2New = <String>[
  'lib/security/timeline/intruder_outcome_journal_adapter.dart',
  'lib/security/timeline/security_timeline_grouping.dart',
  'lib/app/protection_health_journal_recorder.dart',
  'lib/security/timeline/storage_health_journal_sampler.dart',
  'lib/ui/screens/security/security_timeline_detail_screen.dart',
];
const List<String> _m2Modified = <String>[
  'lib/security/timeline/security_journal_event.dart',
  'lib/security/timeline/security_event_journal.dart',
  'lib/security/timeline/security_event_journal_store.dart',
  'lib/security/timeline/security_timeline.dart',
  'lib/ui/screens/security/security_timeline_screen.dart',
  'lib/security/intruder/intruder_defense_coordinator.dart',
  'lib/ui/screens/security/intruder_evidence_screen.dart',
  'lib/app/app_container.dart',
];

Iterable<File> _dart(String dir) => Directory(dir)
    .listSync(recursive: true)
    .whereType<File>()
    .where((File f) => f.path.endsWith('.dart'));

String _body(String src, String signature) {
  final int i = src.indexOf(signature);
  expect(i, greaterThanOrEqualTo(0), reason: signature);
  final int end = src.indexOf('\n  }\n', i);
  return src.substring(i, end);
}

void main() {
  group('I-01 differential isolation', () {
    Future<String> run(IntruderOutcomeObserver? Function(AppContainer) obs,
        {InMemoryLocalDatabase? db}) async {
      final GatedEvidenceService p = GatedEvidenceService()
        ..permission = CameraPermissionState.granted;
      final AppContainer c = await _container(db: db, platform: p);
      c.intruderDefense.outcomeObserver = obs(c);
      await c.auth.enrollPin(_pin);
      await c.intruderDefenseSettings.write(const IntruderDefenseSettings(
          evidenceEnabled: true, alarmEnabled: true, threshold: 1));
      final List<String> verdicts = <String>[];
      for (int i = 1; i <= 5; i++) {
        verdicts.add((await _challenge(c, '000000', i))!);
        await c.intruderMonitor.idle();
        await c.intruderDefense.idle();
      }
      final CredentialState s = (await c.auth.status()).valueOrNull!;
      // owner success (after the lockout elapses it would succeed; the
      // verdict itself is part of the comparison either way)
      verdicts.add((await _challenge(c, _pin, 6))!);
      await c.intruderMonitor.idle();
      c.intruderDefense.onOwnerVerified();
      await c.intruderDefense.idle();
      await c.intruderDefenseSettings.write(const IntruderDefenseSettings(
          evidenceEnabled: false, alarmEnabled: false, threshold: 1));
      c.intruderDefense.onSettingsChanged(const IntruderDefenseSettings(
          evidenceEnabled: false, alarmEnabled: false, threshold: 1));
      await c.intruderDefense.idle();
      await Future<void>.delayed(Duration.zero);
      final int photos = (await c.intruderEvidence.list()).length;
      return <Object?>[
        verdicts.join(','),
        s.failedAttempts,
        s.lockoutStreak,
        s.lockedOutUntil != null,
        p.ops.join(','),
        photos,
        _status(c.intruderDefense.status),
      ].join(' / ');
    }

    test(
        'null / always-throwing / journal-with-throwing-DB observers are '
        'indistinguishable to auth, lockout, platform, evidence and status',
        () async {
      final String none = await run((_) => null);
      final String thrown = await run((_) => _ThrowingObserver());
      final String broken = await run(
          (AppContainer c) => IntruderOutcomeJournalAdapter(
              SecurityEventJournal(
                  store: SecurityEventJournalStore(_BrokenJournalDb()))),
          db: _BrokenJournalDb());
      expect(thrown, none);
      expect(broken, none);
      expect(none, contains('capture'));
    });
  });

  group('I-02 end to end (data path)', () {
    test(
        'challenge failures → threshold → photo saved → captureSaved(trig) → '
        'grouped with its failure', () async {
      final AppContainer c = await _container();
      await c.auth.enrollPin(_pin);
      await c.intruderDefenseSettings.write(const IntruderDefenseSettings(
          evidenceEnabled: true, alarmEnabled: false, threshold: 2));
      for (int i = 1; i <= 2; i++) {
        await _challenge(c, '000000', i);
        await c.intruderMonitor.idle();
        await c.intruderDefense.idle();
      }
      await Future<void>.delayed(Duration.zero);
      await c.securityJournal.idle();
      final List<EvidenceItem> photos = await c.intruderEvidence.list();
      expect(photos.length, 1);
      final SecurityTimelineSnapshot s = await c.securityTimeline.load();
      final List<TimelineRow> rows = buildTimelineRows(s.entries);
      final TimelineFailureGroup g =
          rows.whereType<TimelineFailureGroup>().single;
      expect(g.count, 2);
      expect(g.has(TimelineEntryKind.captureSaved), isTrue);
      expect(g.outcomes.single.trig, photos.single.seq);
      expect(
          rows
              .whereType<TimelineEntryRow>()
              .where((TimelineEntryRow r) => r.detachedOutcome),
          isEmpty);
    });
  });

  group('I-03 restart', () {
    test(
        'identical v2 events and order after restart; first: true again only '
        'on a changed health state', () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final InMemorySecretStore ss = InMemorySecretStore();
      final AppContainer a = await _container(db: db, secrets: ss);
      a.securityJournal.record(SecurityJournalEventType.journalRecovered);
      a.securityJournal.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(3));
      a.securityJournal.recordHealthObservation(
          HState.offline, <HCode>[HCode.detectionOffline]);
      await a.securityJournal.idle();
      final List<String> before = (await a.securityJournal.read())
          .events
          .map((SecurityJournalEvent e) => '${e.seq}:${e.type.name}')
          .toList();
      final AppContainer b = await _container(db: db, secrets: ss);
      final List<String> after = (await b.securityJournal.read())
          .events
          .map((SecurityJournalEvent e) => '${e.seq}:${e.type.name}')
          .toList();
      expect(after, before);
      b.securityJournal.recordHealthObservation(
          HState.offline, <HCode>[HCode.detectionOffline]);
      await b.securityJournal.idle();
      expect((await b.securityJournal.read()).events.length, before.length,
          reason: 'same state after restart ⇒ nothing');
      b.securityJournal.recordHealthObservation(
          HState.attention, <HCode>[HCode.overlayUnavailable]);
      await b.securityJournal.idle();
      final SecurityJournalEvent last =
          (await b.securityJournal.read()).events.last;
      expect(last.type, SecurityJournalEventType.protectionHealth);
      expect((last.fields! as ProtectionHealthFields).first, isFalse,
          reason: 'first is per process: the offline observation came first');
    });

    test('seeding when the row is missing: boot + health ⇒ row stays null',
        () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final AppContainer c = await _container(db: db);
      c.securityJournal.recordHealthObservation(
          HState.offline, <HCode>[HCode.detectionOffline]);
      await c.securityJournal.idle();
      expect(await db.getSetting(_jKey), isNull);
    });
  });

  group('I-04 TL-3', () {
    test(
        'timeline load + journal read leave failure log, evidence index, '
        'intruder settings and credential rows byte-identical', () async {
      final _KeysDb db = _KeysDb();
      final AppContainer c = await _container(db: db);
      await c.auth.enrollPin(_pin);
      await c.intruderDefenseSettings.write(const IntruderDefenseSettings(
          evidenceEnabled: true, alarmEnabled: false, threshold: 9));
      await c.intruderEvidence.save(seq: 1, jpeg: jpegWithMetadata());
      await _challenge(c, '000000', 1);
      await c.intruderMonitor.idle();
      final Map<String, String?> snap = <String, String?>{
        for (final String k
            in db.written.where((String k) => !k.startsWith(_jKey)))
          k: await db.getSetting(k),
      };
      expect(
          snap.keys,
          containsAll(<String>[
            IntruderFailureLogStore.storageKey,
            IntruderEvidenceStore.indexKey,
          ]));
      db.written.clear();
      await c.securityTimeline.load();
      await c.securityTimeline.load();
      await c.securityJournal.read();
      await c.securityJournal.idle();
      expect(db.written.where((String k) => !k.startsWith(_jKey)), isEmpty);
      for (final MapEntry<String, String?> e in snap.entries) {
        expect(await db.getSetting(e.key), e.value, reason: e.key);
      }
    });
  });

  group('F-05 / F-05b process death', () {
    test(
        'F-05 journal discarded with 10 queued ops ⇒ a new container sees '
        'the last committed row only; nothing fabricated', () async {
      final InMemoryLocalDatabase db = InMemoryLocalDatabase();
      final InMemorySecretStore ss = InMemorySecretStore();
      final AppContainer a = await _container(db: db, secrets: ss);
      a.securityJournal.recordEvent(
          SecurityJournalEventType.captureSaved, const CaptureSavedFields(1));
      await a.securityJournal.idle();
      final String committed = (await db.getSetting(_jKey))!;
      // A second journal over the same row whose queue never drains: its
      // ops are enqueued but the instance is dropped before they run.
      final SecurityEventJournal doomed =
          SecurityEventJournal(store: SecurityEventJournalStore(_StallDb(db)));
      for (int i = 0; i < 10; i++) {
        doomed.recordEvent(
            SecurityJournalEventType.captureSaved, CaptureSavedFields(100 + i));
      }
      final AppContainer b = await _container(db: db, secrets: ss);
      final SecurityJournalView v = await b.securityJournal.read();
      expect(await db.getSetting(_jKey), committed);
      expect(
          v.events
              .where((SecurityJournalEvent e) =>
                  e.type == SecurityJournalEventType.captureSaved)
              .map((SecurityJournalEvent e) => e.fields!.trig),
          <int>[1]);
    });

    test(
        'F-05b crash after save=saved and before the adapter microtask ⇒ the '
        'photo is listed; the group has no outcome (never "not saved")',
        () async {
      final AppContainer c = await _container();
      c.intruderDefense.outcomeObserver = _NoopObserver(); // record never runs
      await c.auth.enrollPin(_pin);
      await c.intruderDefenseSettings.write(const IntruderDefenseSettings(
          evidenceEnabled: true, alarmEnabled: false, threshold: 1));
      await _challenge(c, '000000', 1);
      await c.intruderMonitor.idle();
      await c.intruderDefense.idle();
      expect((await c.intruderEvidence.list()).length, 1);
      final SecurityTimelineSnapshot s = await c.securityTimeline.load();
      final TimelineFailureGroup g =
          buildTimelineRows(s.entries).whereType<TimelineFailureGroup>().single;
      expect(g.outcomes, isEmpty);
      expect(g.has(TimelineEntryKind.captureNotSaved), isFalse);
      expect(
          _src('lib/ui/screens/security/security_timeline_detail_screen.dart'),
          contains("Key('security_timeline_detail_outcome_not_recorded')"));
    });
  });

  group('static checks', () {
    test('S-01 no logging / sharing / file / network APIs in M2 files', () {
      final RegExp bad = RegExp(
          r'\bprint\(|debugPrint|\blog\(|developer\.log|Clipboard|\bShare\b|'
          r'SelectableText\(|\bFile\(|HttpClient|\bSocket\b|launchUrl');
      for (final String f in <String>[..._m2New, ..._m2Modified]) {
        final List<String> hits = _src(f)
            .split('\n')
            .where((String l) => !l.trimLeft().startsWith('//'))
            .where(bad.hasMatch)
            .toList();
        expect(hits, isEmpty, reason: f);
      }
    });

    test(
        'S-02 import graph: enforcement / credentials / protection / '
        'intruder never import the timeline; the journal core imports no '
        'protection code', () {
      final RegExp timelineImport =
          RegExp(r'''import\s+'[^']*security/timeline/''');
      final RegExp relTimeline = RegExp(r'''import\s+'(\.\./)+timeline/''');
      final List<File> guarded = <File>[
        ..._dart('lib/security/credentials'),
        ..._dart('lib/protection'),
        ..._dart('lib/security/intruder'),
        File('lib/app/lock_challenge_host.dart'),
        if (File('lib/app/challenge_auth_recorder.dart').existsSync())
          File('lib/app/challenge_auth_recorder.dart'),
      ];
      for (final File f in guarded) {
        final String s = f.readAsStringSync();
        expect(timelineImport.hasMatch(s) || relTimeline.hasMatch(s), isFalse,
            reason: f.path);
        expect(s.contains('protection_health_journal_recorder'), isFalse,
            reason: f.path);
      }
      for (final File f in _dart('lib/security/timeline')) {
        expect(f.readAsStringSync().contains('protection/'), isFalse,
            reason: f.path);
      }
    });

    test('S-03 timeline files never touch the evidence store or settings rows',
        () {
      final List<String> files = <String>[
        ..._dart('lib/security/timeline').map((File f) => f.path),
        'lib/ui/screens/security/security_timeline_screen.dart',
        'lib/ui/screens/security/security_timeline_detail_screen.dart',
        'lib/app/protection_health_journal_recorder.dart',
      ];
      final RegExp bad = RegExp(r'IntruderEvidenceStore|intruderEvidence\.|'
          r'readImage\(|\.summary\(|enforceRetention\(|clearAll\(|'
          r'intruderEvidence\.delete\(');
      for (final String f in files) {
        final String s = _src(f);
        expect(bad.hasMatch(s), isFalse, reason: f);
        if (!f.endsWith('security_event_journal_store.dart')) {
          expect(s.contains('setSetting'), isFalse, reason: f);
        }
      }
    });

    test(
        'S-04 no await / then / Future / Completer in the notify path or the '
        "adapter's onIntruderOutcome", () {
      final String coord =
          _src('lib/security/intruder/intruder_defense_coordinator.dart');
      final String adapter =
          _src('lib/security/timeline/intruder_outcome_journal_adapter.dart');
      final RegExp bad = RegExp(r'\bawait\b|\.then\(|\bFuture\b|\bCompleter\b');
      for (final String b in <String>[
        _body(coord, 'void _notify(IntruderOutcome o) {'),
        _body(coord, 'void _notifyCapture(IntruderOutcome o) {'),
        _body(adapter, 'void onIntruderOutcome(IntruderOutcome o) {'),
      ]) {
        expect(bad.hasMatch(b), isFalse, reason: b);
      }
    });

    test('S-05 the three verification / viewer entry counts are unchanged', () {
      int count(RegExp r) => _dart('lib')
          .map((File f) => r.allMatches(f.readAsStringSync()).length)
          .fold(0, (int a, int b) => a + b);
      expect(count(RegExp(r'(?<!const )\bIntruderEvidenceDetailScreen\(')), 1);
      expect(count(RegExp(r'intruderOwnerSessions\.begin\(')), 1);
      expect(
          count(RegExp(r'verifyIntruderOwner\(navigator, container\.auth\)')),
          3);
    });

    test('S-06 no deep link to details or evidence in the router', () {
      final String r = _src('lib/app/router.dart');
      expect(r.contains('/security/timeline/detail'), isFalse);
      expect(r.contains('intruder_evidence'), isFalse);
      expect(r.contains('IntruderEvidence'), isFalse);
    });
  });
}

class _KeysDb extends InMemoryLocalDatabase {
  final List<String> written = <String>[];
  @override
  Future<void> setSetting(String key, String value) {
    if (!written.contains(key)) written.add(key);
    return super.setSetting(key, value);
  }
}

/// Delegates to [inner] but never completes journal reads (the process
/// "dies" with ops queued).
class _StallDb extends InMemoryLocalDatabase {
  _StallDb(this.inner);
  final InMemoryLocalDatabase inner;
  @override
  Future<String?> getSetting(String key) => key.startsWith(_jKey)
      ? Completer<String?>().future
      : inner.getSetting(key);
  @override
  Future<void> setSetting(String key, String value) =>
      inner.setSetting(key, value);
}
