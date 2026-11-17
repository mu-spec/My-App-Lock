import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/services.dart';

/// F-KEY-1 / K-2+B-compat: a data key wrapped under a non-exportable key
/// encryption key (KEK). [alias] names the KEK (unique per wrap; never
/// reused, never deleted automatically); [blob] is `iv || ct || tag`
/// (base64).
final class WrappedKey {
  const WrappedKey({required this.alias, required this.blob});
  final String alias;
  final String blob;
}

/// The KEK is gone (e.g. backup/D2D restore, Keystore reset): the wrapped
/// copy can never be unwrapped again.
final class KeyWrapMissing implements Exception {
  const KeyWrapMissing();
  @override
  String toString() => 'KeyWrapMissing';
}

/// Wrapping is unavailable or failed for a reason that may be transient
/// (no native channel, Keystore busy, authentication failure on the blob).
final class KeyWrapUnavailable implements Exception {
  const KeyWrapUnavailable(this.code);
  final String code;
  @override
  String toString() => 'KeyWrapUnavailable($code)';
}

/// Wraps/unwraps the master data key under a platform KEK.
abstract interface class KeyWrapper {
  /// Wraps [key] under a NEW KEK with a fresh unique alias.
  Future<WrappedKey> wrapNew(Uint8List key);

  /// Unwraps [wrapped]. Throws [KeyWrapMissing] when the KEK no longer
  /// exists, [KeyWrapUnavailable] otherwise.
  Future<Uint8List> unwrap(WrappedKey wrapped);
}

/// No platform KEK (tests, unsupported engines). Every call is
/// unavailable; the resolver then runs without a wrapped copy.
final class NoKeyWrapper implements KeyWrapper {
  const NoKeyWrapper();
  @override
  Future<WrappedKey> wrapNew(Uint8List key) async =>
      throw const KeyWrapUnavailable('none');
  @override
  Future<Uint8List> unwrap(WrappedKey wrapped) async =>
      throw const KeyWrapUnavailable('none');
}

/// Production: AndroidKeyStore KEK via `smart_app_lock/key_wrap`
/// (`KeyWrapChannel.kt`). A missing plugin (engine without the channel)
/// is reported as unavailable, never as success.
final class MethodChannelKeyWrapper implements KeyWrapper {
  const MethodChannelKeyWrapper(
      [this._channel = const MethodChannel('smart_app_lock/key_wrap')]);
  final MethodChannel _channel;

  @override
  Future<WrappedKey> wrapNew(Uint8List key) async {
    try {
      final Map<Object?, Object?>? r = await _channel
          .invokeMapMethod<Object?, Object?>(
              'wrapNew', <String, Object?>{'key': base64Encode(key)});
      final Object? alias = r?['alias'];
      final Object? blob = r?['blob'];
      if (alias is! String || blob is! String) {
        throw const KeyWrapUnavailable('malformed');
      }
      return WrappedKey(alias: alias, blob: blob);
    } on PlatformException catch (e) {
      throw KeyWrapUnavailable(e.code);
    } on MissingPluginException {
      throw const KeyWrapUnavailable('no_channel');
    }
  }

  @override
  Future<Uint8List> unwrap(WrappedKey wrapped) async {
    try {
      final String? r = await _channel.invokeMethod<String>('unwrap',
          <String, Object?>{'alias': wrapped.alias, 'blob': wrapped.blob});
      if (r == null) throw const KeyWrapUnavailable('malformed');
      return Uint8List.fromList(base64Decode(r));
    } on PlatformException catch (e) {
      if (e.code == 'key_missing') throw const KeyWrapMissing();
      throw KeyWrapUnavailable(e.code);
    } on MissingPluginException {
      throw const KeyWrapUnavailable('no_channel');
    } on FormatException {
      throw const KeyWrapUnavailable('malformed');
    }
  }
}

/// Test double modelling the Keystore: one random KEK per alias, held in
/// memory (shared by every resolver given the same instance = one
/// "device"). [loseAllKeks] models a backup/D2D restore or Keystore reset.
final class InMemoryKeyWrapper implements KeyWrapper {
  InMemoryKeyWrapper({Random? random}) : _random = random ?? Random.secure();
  final Random _random;
  final AesGcm _gcm = AesGcm.with256bits();
  final Map<String, List<int>> _keks = <String, List<int>>{};
  int wraps = 0;
  int unwraps = 0;

  /// When set, the next call throws this (then clears).
  Exception? failNext;

  Iterable<String> get aliases => _keks.keys;

  void loseAllKeks() => _keks.clear();

  List<int> _bytes(int n) => List<int>.generate(n, (_) => _random.nextInt(256));

  @override
  Future<WrappedKey> wrapNew(Uint8List key) async {
    final Exception? f = failNext;
    if (f != null) {
      failNext = null;
      throw f;
    }
    wraps++;
    final String alias =
        'sal_kek_${_bytes(8).map((int b) => b.toRadixString(16).padLeft(2, '0')).join()}';
    final List<int> kek = _bytes(32);
    _keks[alias] = kek;
    final SecretBox box =
        await _gcm.encrypt(key, secretKey: SecretKey(kek), nonce: _bytes(12));
    return WrappedKey(
        alias: alias,
        blob: base64Encode(box.concatenation(nonce: true, mac: true)));
  }

  @override
  Future<Uint8List> unwrap(WrappedKey wrapped) async {
    final Exception? f = failNext;
    if (f != null) {
      failNext = null;
      throw f;
    }
    unwraps++;
    final List<int>? kek = _keks[wrapped.alias];
    if (kek == null) throw const KeyWrapMissing();
    try {
      final SecretBox box = SecretBox.fromConcatenation(
          base64Decode(wrapped.blob),
          nonceLength: 12,
          macLength: 16);
      return Uint8List.fromList(
          await _gcm.decrypt(box, secretKey: SecretKey(kek)));
    } catch (_) {
      throw const KeyWrapUnavailable('unwrap_failed');
    }
  }
}
