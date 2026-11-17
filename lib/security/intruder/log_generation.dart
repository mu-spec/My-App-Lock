// P13/M3 Batch 3 (B2 §2 / P4 §2): the failure-log generation id.
//
// 16 bytes from a CRYPTOGRAPHICALLY SECURE generator, base64url without
// padding (exactly 22 chars). Never derived from the clock, device ids,
// package names or secrets; never reused; never shown or exported. If no
// secure generator exists, minting throws [UnsupportedError] and the caller
// fails closed: there is deliberately NO fallback to `Random()`.
import 'dart:convert';
import 'dart:math';

abstract final class LogGeneration {
  static final RegExp _pattern = RegExp(r'^[A-Za-z0-9_-]{22}$');

  /// True only for a well-formed generation id (anything else = corrupt).
  static bool isValid(Object? value) =>
      value is String && _pattern.hasMatch(value);

  /// Mints a fresh id. [secure] is for tests only; production always uses
  /// `Random.secure()`, whose [UnsupportedError] propagates (fail closed).
  static String mint([Random? secure]) {
    final Random r = secure ?? Random.secure();
    final List<int> bytes = List<int>.generate(16, (_) => r.nextInt(256));
    final String id = base64Url.encode(bytes).replaceAll('=', '');
    assert(isValid(id));
    return id;
  }
}
