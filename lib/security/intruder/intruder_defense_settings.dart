// Phase 12 / Milestone 2 — Intruder Defense owner settings.
//
// The owner's explicit opt-ins for camera evidence and the alarm, plus the
// configured failure threshold. Stored as ONE encrypted row in the existing
// LocalDatabase settings table, separate from the credential document (the
// auth core is not touched). Privacy fail-safe: anything unreadable,
// corrupt or written by a newer schema reads as DISABLED and is never
// overwritten. This record controls evidence and the alarm only — it is
// never consulted for any access decision.

import 'dart:async';
import 'dart:collection';
import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import '../../data/storage/local_database.dart';
import '../encryption/master_key_resolver.dart';
import '../encryption/settings_cipher.dart';

/// The owner's intruder-defense choices. Everything defaults to off.
final class IntruderDefenseSettings {
  const IntruderDefenseSettings({
    this.evidenceEnabled = false,
    this.alarmEnabled = false,
    this.threshold = defaultThreshold,
    this.historyRetentionDays = defaultHistoryRetentionDays,
    this.invalidRetention,
  });

  static const int schemaVersion = 1;
  static const int defaultThreshold = 3;
  static const int minThreshold = 1;
  static const int maxThreshold = 10;

  /// Batch 5 (F-2): history retention choices, in days, and the default
  /// (today's behaviour). Evidence retention is separate and fixed.
  static const List<int> historyRetentionChoices = <int>[7, 30, 90];
  static const int defaultHistoryRetentionDays = 30;

  static const IntruderDefenseSettings disabled = IntruderDefenseSettings();

  /// Camera evidence after the threshold (requires CAMERA permission).
  final bool evidenceEnabled;

  /// Audible alarm after the threshold.
  final bool alarmEnabled;

  /// Consecutive verified failures that trigger evidence / alarm.
  final int threshold;

  /// Batch 5: history retention in days (always one of
  /// [historyRetentionChoices]). Stored as the optional `hr` only when not
  /// the default, so a default record stays byte-identical to Phase 12.
  final int historyRetentionDays;

  /// Batch 5: a stored `hr` that is not a valid choice. Such a value means
  /// the default (30 — never the shortest), raises [retentionInvalid] and
  /// is written back unchanged by unrelated updates (never silently
  /// replaced); only an explicit retention choice replaces it.
  final InvalidRetentionValue? invalidRetention;

  bool get retentionInvalid => invalidRetention != null;

  IntruderDefenseSettings copyWith({
    bool? evidenceEnabled,
    bool? alarmEnabled,
    int? threshold,
    int? historyRetentionDays,
  }) =>
      IntruderDefenseSettings(
        evidenceEnabled: evidenceEnabled ?? this.evidenceEnabled,
        alarmEnabled: alarmEnabled ?? this.alarmEnabled,
        threshold: threshold ?? this.threshold,
        historyRetentionDays: historyRetentionDays ?? this.historyRetentionDays,
        // An explicit retention choice replaces an invalid stored value.
        invalidRetention:
            historyRetentionDays == null ? invalidRetention : null,
      );

  Map<String, Object?> toJson() => <String, Object?>{
        'v': schemaVersion,
        'evidence': evidenceEnabled,
        'alarm': alarmEnabled,
        'threshold': threshold,
        if (historyRetentionDays != defaultHistoryRetentionDays)
          'hr': historyRetentionDays
        else if (invalidRetention != null)
          'hr': invalidRetention!.raw,
      };

  /// Strict decode; throws [FormatException] on anything unexpected.
  static IntruderDefenseSettings fromJson(Object? raw) {
    if (raw is! Map ||
        raw['v'] != schemaVersion ||
        raw['evidence'] is! bool ||
        raw['alarm'] is! bool ||
        raw['threshold'] is! int) {
      throw const FormatException('intruder defense settings');
    }
    final int t = raw['threshold'] as int;
    if (t < minThreshold || t > maxThreshold) {
      throw const FormatException('threshold out of range');
    }
    // Batch 5: optional `hr`; absent -> 30; invalid -> 30 + health flag
    // (the record itself stays valid: an older build ignores `hr`).
    final Object? hr = raw['hr'];
    final bool hrValid = hr is int && historyRetentionChoices.contains(hr);
    return IntruderDefenseSettings(
      evidenceEnabled: raw['evidence'] as bool,
      alarmEnabled: raw['alarm'] as bool,
      threshold: t,
      historyRetentionDays: hrValid ? hr : defaultHistoryRetentionDays,
      invalidRetention:
          raw.containsKey('hr') && !hrValid ? InvalidRetentionValue(hr) : null,
    );
  }

  @override
  bool operator ==(Object other) =>
      other is IntruderDefenseSettings &&
      other.evidenceEnabled == evidenceEnabled &&
      other.alarmEnabled == alarmEnabled &&
      other.threshold == threshold &&
      other.historyRetentionDays == historyRetentionDays &&
      other.invalidRetention == invalidRetention;

  @override
  int get hashCode => Object.hash(evidenceEnabled, alarmEnabled, threshold,
      historyRetentionDays, invalidRetention);
}

/// Batch 5: an invalid stored `hr`, kept verbatim so it is written back
/// unchanged by unrelated settings updates.
final class InvalidRetentionValue {
  const InvalidRetentionValue(this.raw);

  final Object? raw;

  @override
  bool operator ==(Object other) =>
      other is InvalidRetentionValue &&
      jsonEncode(other.raw) == jsonEncode(raw);

  @override
  int get hashCode => jsonEncode(raw).hashCode;
}

/// Why the stored settings are (or are not) in effect.
enum IntruderSettingsHealth { ok, missing, corrupt, unsupported, unreadable }

final class IntruderSettingsRead {
  const IntruderSettingsRead(this.settings, this.health);

  /// The settings in effect — [IntruderDefenseSettings.disabled] unless
  /// [health] is ok.
  final IntruderDefenseSettings settings;
  final IntruderSettingsHealth health;

  /// Only a missing or valid record may be replaced; a corrupt, newer or
  /// unreadable one is never overwritten.
  bool get writable =>
      health == IntruderSettingsHealth.ok ||
      health == IntruderSettingsHealth.missing;
}

/// Encrypted persistence for [IntruderDefenseSettings]. A cipher is
/// mandatory: there is no plaintext mode.
class IntruderDefenseSettingsStore {
  IntruderDefenseSettingsStore(this._database, this._cipher);

  static const String storageKey = 'intruder_defense_settings';
  static const String _prefix = 'enc:v1:';

  final LocalDatabase _database;
  final SettingsCipher _cipher;

  Future<IntruderSettingsRead> read() async {
    final String? raw;
    try {
      raw = await _database.getSetting(storageKey);
    } catch (_) {
      return const IntruderSettingsRead(
          IntruderDefenseSettings.disabled, IntruderSettingsHealth.unreadable);
    }
    if (raw == null) {
      return const IntruderSettingsRead(
          IntruderDefenseSettings.disabled, IntruderSettingsHealth.missing);
    }
    if (!raw.startsWith(_prefix)) {
      return const IntruderSettingsRead(
          IntruderDefenseSettings.disabled, IntruderSettingsHealth.corrupt);
    }
    final String clear;
    try {
      clear = await _cipher.decryptString(raw.substring(_prefix.length));
    } on MasterKeyUnavailableException {
      // F-KEY-1 (Batch 2): no verified key right now. UNREADABLE, never
      // corrupt: the record is not the problem and is never replaced.
      return const IntruderSettingsRead(
          IntruderDefenseSettings.disabled, IntruderSettingsHealth.unreadable);
    } on SecretBoxAuthenticationError {
      // Wrong/missing key and damaged bytes are indistinguishable under
      // AES-GCM (same rule as the R9 stores): unreadable, preserved.
      return const IntruderSettingsRead(
          IntruderDefenseSettings.disabled, IntruderSettingsHealth.unreadable);
    } catch (_) {
      // Structurally impossible ciphertext (not base64 / too short): no key
      // can ever open it.
      return const IntruderSettingsRead(
          IntruderDefenseSettings.disabled, IntruderSettingsHealth.corrupt);
    }
    final Object? decoded;
    try {
      decoded = jsonDecode(clear);
    } catch (_) {
      return const IntruderSettingsRead(
          IntruderDefenseSettings.disabled, IntruderSettingsHealth.corrupt);
    }
    if (decoded is Map &&
        decoded['v'] is int &&
        (decoded['v'] as int) > IntruderDefenseSettings.schemaVersion) {
      return const IntruderSettingsRead(
          IntruderDefenseSettings.disabled, IntruderSettingsHealth.unsupported);
    }
    try {
      return IntruderSettingsRead(
          IntruderDefenseSettings.fromJson(decoded), IntruderSettingsHealth.ok);
    } on FormatException {
      return const IntruderSettingsRead(
          IntruderDefenseSettings.disabled, IntruderSettingsHealth.corrupt);
    }
  }

  /// Saves [settings]. Returns false (and writes nothing) when the current
  /// record must not be overwritten, or when the write fails.
  Future<bool> write(IntruderDefenseSettings settings) =>
      _serial(() => _writeUnlocked(settings));

  Future<bool> _writeUnlocked(IntruderDefenseSettings settings) async {
    if (!_inRange(settings.threshold)) return false;
    final IntruderSettingsRead current = await read();
    if (!current.writable) {
      return false;
    }
    try {
      final String enc =
          await _cipher.encryptString(jsonEncode(settings.toJson()));
      await _database.setSetting(storageKey, '$_prefix$enc');
      return true;
    } catch (_) {
      return false;
    }
  }

  static bool _inRange(int t) =>
      t >= IntruderDefenseSettings.minThreshold &&
      t <= IntruderDefenseSettings.maxThreshold;

  /// Phase 12 / M3 — serialized read-modify-write. Re-reads the
  /// authoritative record, refuses when it is not writable (corrupt /
  /// newer / unreadable — never overwritten), applies [transform], validates
  /// the threshold range and writes. Returns the record now persisted, or
  /// null when nothing was written. Callers must have a FRESH owner
  /// verification (UI responsibility; this store never authorizes).
  Future<IntruderDefenseSettings?> update(
    IntruderDefenseSettings Function(IntruderDefenseSettings current) transform,
  ) =>
      _serial(() async {
        final IntruderSettingsRead current = await read();
        if (!current.writable) return null;
        final IntruderDefenseSettings next = transform(current.settings);
        return await _writeUnlocked(next) ? next : null;
      });

  // Zone-safe FIFO lock (same design as the evidence store's).
  bool _held = false;
  final Queue<Completer<void>> _waiters = Queue<Completer<void>>();

  Future<T> _serial<T>(Future<T> Function() op) async {
    if (_held) {
      final Completer<void> turn = Completer<void>();
      _waiters.add(turn);
      await turn.future;
    } else {
      _held = true;
    }
    try {
      return await op();
    } finally {
      if (_waiters.isEmpty) {
        _held = false;
      } else {
        _waiters.removeFirst().complete();
      }
    }
  }
}
