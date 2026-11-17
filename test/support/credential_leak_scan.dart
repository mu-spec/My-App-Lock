// Phase 14 final verification: structural credential-leak scan for stored
// JSON documents (fixes a time/random-dependent false positive in the
// Phase 12 "attempted PIN never appears in the stored log" test).
//
// The old check was `expect(plain, isNot(contains(pin)))` on the whole JSON
// text. Fields that are generated independently of any credential (a
// wall-clock timestamp, a random log generation, a random verification
// nonce) could contain the PIN's digits by chance, e.g. `at:1794913742731`
// contains "9137".
//
// This scan is at least as strict everywhere else:
//  * every key and every string or number in the document, at any depth,
//    must not contain any secret (substring, as before). Unknown or new
//    fields are therefore always fully checked;
//  * ONLY the paths listed in [opaque] skip the substring test. Each must
//    instead pass its strict validator, which ties it to a value that
//    cannot carry a secret (for example a timestamp inside the attempt's
//    time window, or an exact random-id format). A validator failure is a
//    finding;
//  * an opaque path that is missing is not a finding; a present but
//    invalid one is.
// Paths: `key`, `parent.key`, list items as `[]`, e.g. `events[].at`.
import 'dart:convert';

typedef OpaqueValidator = bool Function(Object? value);

/// Returns human-readable findings; empty = no secret found.
List<String> findCredentialLeaks(
  String json,
  Iterable<String> secrets, {
  Map<String, OpaqueValidator> opaque = const <String, OpaqueValidator>{},
}) {
  final List<String> needles = secrets.toList(growable: false);
  if (needles.isEmpty || needles.any((String s) => s.isEmpty)) {
    throw ArgumentError('secrets must be non-empty');
  }
  final List<String> findings = <String>[];
  final Object? doc = jsonDecode(json);

  void checkText(String path, String text, String what) {
    for (final String s in needles) {
      if (text.contains(s)) findings.add('$what at $path contains a secret');
    }
  }

  void walk(Object? node, String path) {
    if (node is Map) {
      node.forEach((Object? k, Object? v) {
        final String key = '$k';
        final String child = path.isEmpty ? key : '$path.$key';
        checkText(child, key, 'key');
        final OpaqueValidator? validator = opaque[child];
        if (validator != null) {
          if (!validator(v)) findings.add('opaque field $child is invalid');
          return;
        }
        walk(v, child);
      });
    } else if (node is List) {
      for (final Object? e in node) {
        walk(e, '$path[]');
      }
    } else if (node is String) {
      checkText(path, node, 'string');
    } else if (node is num) {
      checkText(path, node.toString(), 'number');
    }
  }

  walk(doc, '');
  return findings;
}

/// Validator: an int timestamp (ms since epoch) within [from, to].
OpaqueValidator timestampWithin(DateTime from, DateTime to) => (Object? v) =>
    v is int &&
    v >= from.millisecondsSinceEpoch &&
    v <= to.millisecondsSinceEpoch;

/// Validator: `<16 lowercase hex>:<counter>` (the credential manager's
/// random instance nonce plus its verification counter). The counter part
/// is still checked against [secrets]; only the random nonce is exempt.
OpaqueValidator verificationId(Iterable<String> secrets) {
  final RegExp shape = RegExp(r'^[0-9a-f]{16}:([1-9][0-9]{0,5})$');
  final List<String> needles = secrets.toList(growable: false);
  return (Object? v) {
    if (v is! String) return false;
    final RegExpMatch? m = shape.firstMatch(v);
    if (m == null) return false;
    final String counter = m.group(1)!;
    return !needles.any(counter.contains);
  };
}
