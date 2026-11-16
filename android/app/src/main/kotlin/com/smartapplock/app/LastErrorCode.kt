package com.smartapplock.app

import android.os.Build

/**
 * P13/M3 NF-RG-1: the ONLY values that may be persisted as the watcher's last
 * error. Exception text (message, cause, stack) is never stored, returned or
 * displayed; a code is selected from the failure CLASS only.
 *
 * Storage (ProtectionStateStore): `last_error_code` = "v1:<wire>" is
 * authoritative; `last_error` = [neutralText] is kept for downgrade
 * compatibility and change detection. Both are written in ONE editor.
 */
enum class LastErrorCode(val wire: String, val neutralText: String) {
    BOOT_RESTART_FAILED(
        "boot_restart_failed",
        "Protection service could not restart after boot.",
    ),
    SECURITY_LEVELS_INVALID(
        "security_levels_invalid",
        "Saved security levels could not be used; the strictest level is enforced.",
    ),
    CHANNEL_CALL_FAILED(
        "channel_call_failed",
        "A protection request could not be completed.",
    ),
    WATCHER_INTERRUPTED(
        "watcher_interrupted",
        WatcherTeardownPolicy.INTERRUPTED_MESSAGE,
    ),
    WATCHER_START_FAILED(
        "watcher_start_failed",
        "Protection service could not start.",
    ),
    WATCHER_START_NOT_ALLOWED(
        "watcher_start_not_allowed",
        "Android did not allow the protection service to start in the background.",
    ),
    OVERLAY_UNAVAILABLE(
        "overlay_unavailable",
        "Overlay permission is unavailable; lock presentation is unavailable.",
    ),
    CHALLENGE_LAUNCH_BLOCKED(
        "challenge_launch_blocked",
        "Android blocked the challenge activity; recovery shield remains active.",
    ),
    EMERGENCY_HIDE_FAILED(
        "emergency_hide_failed",
        "Emergency Home exit released state but shield hide failed.",
    ),
    UNKNOWN("unknown", "An internal problem was recorded.");

    companion object {
        private val WIRE = Regex("^v1:([a-z_]{1,40})$")

        fun encode(c: LastErrorCode): String = "v1:${c.wire}"

        /** Never echoes input. Anything not exactly recognised -> UNKNOWN. */
        fun decode(stored: String?): LastErrorCode? {
            if (stored == null) return null
            val m = WIRE.matchEntire(stored) ?: return UNKNOWN
            return entries.firstOrNull { it.wire == m.groupValues[1] } ?: UNKNOWN
        }

        /** Legacy (pre-NF-RG-1) `last_error` text -> code. Exact matches only. */
        fun fromLegacy(text: String): LastErrorCode = when (text) {
            ProtectionStateStore.ERROR_LEVELS_INVALID -> SECURITY_LEVELS_INVALID
            else -> entries.firstOrNull { it != UNKNOWN && it.neutralText == text } ?: UNKNOWN
        }

        /** Exception CLASS selects; message/cause/stack are never read. */
        fun forWatcherStart(e: Throwable, sdkInt: Int = Build.VERSION.SDK_INT): LastErrorCode =
            if (e is SecurityException ||
                (sdkInt >= 31 && e is android.app.ForegroundServiceStartNotAllowedException)
            ) {
                WATCHER_START_NOT_ALLOWED
            } else {
                WATCHER_START_FAILED
            }
    }
}
