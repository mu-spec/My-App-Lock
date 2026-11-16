/// P13/M3 NF-RG-1: the Flutter mirror of the native `LastErrorCode` allowlist.
///
/// The native `getHealth` map carries `lastErrorCode` (the wire name) and
/// `lastError` (that code's neutral sentence). Flutter validates AGAIN: only
/// an exactly-known wire name is accepted; the displayed sentence always comes
/// from THIS table, never from the platform map. Anything else is [unknown].
enum WatcherLastErrorCode {
  bootRestartFailed(
    'boot_restart_failed',
    'Protection service could not restart after boot.',
  ),
  securityLevelsInvalid(
    'security_levels_invalid',
    'Saved security levels could not be used; the strictest level is '
        'enforced.',
  ),
  channelCallFailed(
    'channel_call_failed',
    'A protection request could not be completed.',
  ),
  watcherInterrupted(
    'watcher_interrupted',
    'Android stopped the protection service. Screen-off re-lock and '
        'usage-access detection are paused until it restarts. Battery or '
        'background restrictions can cause this.',
  ),
  watcherStartFailed(
    'watcher_start_failed',
    'Protection service could not start.',
  ),
  watcherStartNotAllowed(
    'watcher_start_not_allowed',
    'Android did not allow the protection service to start in the '
        'background.',
  ),
  overlayUnavailable(
    'overlay_unavailable',
    'Overlay permission is unavailable; lock presentation is unavailable.',
  ),
  challengeLaunchBlocked(
    'challenge_launch_blocked',
    'Android blocked the challenge activity; recovery shield remains active.',
  ),
  emergencyHideFailed(
    'emergency_hide_failed',
    'Emergency Home exit released state but shield hide failed.',
  ),
  unknown('unknown', 'An internal problem was recorded.');

  const WatcherLastErrorCode(this.wire, this.neutralText);

  /// Native wire name (`LastErrorCode.wire`).
  final String wire;

  /// The only text Flutter ever shows for this code.
  final String neutralText;

  static final RegExp _wire = RegExp(r'^[a-z_]{1,40}$');

  /// Validates the platform map. Never echoes input:
  ///  * `lastErrorCode` present: exact known wire name, else [unknown];
  ///  * absent (older native build): `lastError` is accepted only when it
  ///    EXACTLY equals a known neutral sentence (or the legacy
  ///    `security_levels_invalid` value), else [unknown];
  ///  * both absent: null (no error recorded).
  static WatcherLastErrorCode? fromNative(Map<dynamic, dynamic> map) {
    if (map.containsKey('lastErrorCode') && map['lastErrorCode'] != null) {
      final Object? raw = map['lastErrorCode'];
      if (raw is! String || !_wire.hasMatch(raw)) return unknown;
      for (final WatcherLastErrorCode c in values) {
        if (c.wire == raw) return c;
      }
      return unknown;
    }
    final Object? text = map['lastError'];
    if (text == null) return null;
    if (text is! String) return unknown;
    if (text == securityLevelsInvalid.wire) return securityLevelsInvalid;
    for (final WatcherLastErrorCode c in values) {
      if (c != unknown && c.neutralText == text) return c;
    }
    return unknown;
  }
}
