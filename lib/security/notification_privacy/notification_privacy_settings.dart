// Phase 14 / M1 — per-app notification privacy settings.
//
// One encrypted row in the existing settings table (same cipher and the
// same fail-closed read rules as the Phase 12 intruder settings): a record
// that cannot be read is never treated as "off" and is never overwritten.
// Only package names and mode ids are stored; notification content is never
// stored anywhere.

import 'dart:async';
import 'dart:collection';
import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import '../../data/storage/local_database.dart';
import '../encryption/master_key_resolver.dart';
import '../encryption/settings_cipher.dart';

/// Per-app mode. Ids are shared with native
/// (`NotificationPrivacyPolicy.Mode`); [rank] orders strictness.
enum NotificationPrivacyMode {
  off('off', 0, 'Off'),
  hideContent('hide_content', 1, 'Hide content'),
  maximum('maximum', 2, 'Maximum privacy');

  const NotificationPrivacyMode(this.id, this.rank, this.label);

  final String id;
  final int rank;
  final String label;

  static NotificationPrivacyMode? fromId(Object? id) {
    for (final NotificationPrivacyMode m in values) {
      if (m.id == id) return m;
    }
    return null;
  }

  /// True when moving from this mode to [next] reveals more.
  bool isWeakenedBy(NotificationPrivacyMode next) => next.rank < rank;
}

final RegExp _package =
    RegExp(r'^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$');

bool isValidNotificationPrivacyPackage(String p) =>
    p.length <= 255 && _package.hasMatch(p);

final class NotificationPrivacySettings {
  const NotificationPrivacySettings(this.apps);

  static const NotificationPrivacySettings empty =
      NotificationPrivacySettings(<String, NotificationPrivacyMode>{});
  static const int schemaVersion = 1;
  static const int maxApps = 500;

  /// Package -> mode. OFF is never stored (absent = off).
  final Map<String, NotificationPrivacyMode> apps;

  NotificationPrivacyMode modeFor(String packageName) =>
      apps[packageName] ?? NotificationPrivacyMode.off;

  NotificationPrivacySettings withMode(
      String packageName, NotificationPrivacyMode mode) {
    final Map<String, NotificationPrivacyMode> next =
        Map<String, NotificationPrivacyMode>.of(apps);
    if (mode == NotificationPrivacyMode.off) {
      next.remove(packageName);
    } else {
      next[packageName] = mode;
    }
    return NotificationPrivacySettings(
        Map<String, NotificationPrivacyMode>.unmodifiable(next));
  }

  Map<String, Object?> toJson() => <String, Object?>{
        'v': schemaVersion,
        'apps': <String, String>{
          for (final MapEntry<String, NotificationPrivacyMode> e
              in apps.entries)
            if (e.value != NotificationPrivacyMode.off) e.key: e.value.id,
        },
      };

  /// Strict decode: any unexpected shape throws [FormatException].
  factory NotificationPrivacySettings.fromJson(Object? raw) {
    if (raw is! Map || raw['v'] != schemaVersion) {
      throw const FormatException('notification privacy: version');
    }
    final Object? apps = raw['apps'];
    if (apps is! Map || apps.length > maxApps) {
      throw const FormatException('notification privacy: apps');
    }
    final Map<String, NotificationPrivacyMode> out =
        <String, NotificationPrivacyMode>{};
    for (final MapEntry<Object?, Object?> e in apps.entries) {
      final Object? k = e.key;
      final NotificationPrivacyMode? m =
          NotificationPrivacyMode.fromId(e.value);
      if (k is! String ||
          !isValidNotificationPrivacyPackage(k) ||
          m == null ||
          m == NotificationPrivacyMode.off) {
        throw const FormatException('notification privacy: entry');
      }
      out[k] = m;
    }
    return NotificationPrivacySettings(
        Map<String, NotificationPrivacyMode>.unmodifiable(out));
  }
}

enum NotificationPrivacyHealth { ok, missing, corrupt, unsupported, unreadable }

final class NotificationPrivacyRead {
  const NotificationPrivacyRead(this.settings, this.health);

  /// Meaningful only when [writable].
  final NotificationPrivacySettings settings;
  final NotificationPrivacyHealth health;

  bool get writable =>
      health == NotificationPrivacyHealth.ok ||
      health == NotificationPrivacyHealth.missing;
}

class NotificationPrivacySettingsStore {
  NotificationPrivacySettingsStore(this._database, this._cipher);

  static const String storageKey = 'notification_privacy_settings';
  static const String _prefix = 'enc:v1:';

  final LocalDatabase _database;
  final SettingsCipher _cipher;

  static const NotificationPrivacyRead _unreadable = NotificationPrivacyRead(
      NotificationPrivacySettings.empty, NotificationPrivacyHealth.unreadable);
  static const NotificationPrivacyRead _corrupt = NotificationPrivacyRead(
      NotificationPrivacySettings.empty, NotificationPrivacyHealth.corrupt);

  Future<NotificationPrivacyRead> read() async {
    final String? raw;
    try {
      raw = await _database.getSetting(storageKey);
    } catch (_) {
      return _unreadable;
    }
    if (raw == null) {
      return const NotificationPrivacyRead(
          NotificationPrivacySettings.empty, NotificationPrivacyHealth.missing);
    }
    if (!raw.startsWith(_prefix)) return _corrupt;
    final String clear;
    try {
      clear = await _cipher.decryptString(raw.substring(_prefix.length));
    } on MasterKeyUnavailableException {
      return _unreadable; // F-KEY-1: no verified key now; never replaced
    } on SecretBoxAuthenticationError {
      return _unreadable; // wrong key or damaged bytes: preserved
    } catch (_) {
      return _corrupt;
    }
    final Object? decoded;
    try {
      decoded = jsonDecode(clear);
    } catch (_) {
      return _corrupt;
    }
    if (decoded is Map &&
        decoded['v'] is int &&
        (decoded['v'] as int) > NotificationPrivacySettings.schemaVersion) {
      return const NotificationPrivacyRead(NotificationPrivacySettings.empty,
          NotificationPrivacyHealth.unsupported);
    }
    try {
      return NotificationPrivacyRead(
          NotificationPrivacySettings.fromJson(decoded),
          NotificationPrivacyHealth.ok);
    } on FormatException {
      return _corrupt;
    }
  }

  /// Serialized read-modify-write. Refuses (returns null, writes nothing)
  /// when the stored record is not writable. Callers must have verified the
  /// owner where required (UI responsibility; the store never authorizes).
  Future<NotificationPrivacySettings?> update(
    NotificationPrivacySettings Function(NotificationPrivacySettings current)
        transform,
  ) =>
      _serial(() async {
        final NotificationPrivacyRead current = await read();
        if (!current.writable) return null;
        final NotificationPrivacySettings next = transform(current.settings);
        if (next.apps.length > NotificationPrivacySettings.maxApps ||
            next.apps.keys
                .any((String p) => !isValidNotificationPrivacyPackage(p))) {
          return null;
        }
        try {
          final String enc =
              await _cipher.encryptString(jsonEncode(next.toJson()));
          await _database.setSetting(storageKey, '$_prefix$enc');
          return next;
        } catch (_) {
          return null;
        }
      });

  // Zone-safe FIFO lock (same design as the intruder settings store).
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
