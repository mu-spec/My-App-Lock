package com.smartapplock.app

/**
 * Phase 18 / M1F (F18-2): the reply of `smart_app_lock/monotonic_clock`.
 * Pure (JVM-testable): the channel passes in `SystemClock.elapsedRealtime()`
 * (counts deep sleep, cannot be set by the user, restarts at every boot) and
 * `Settings.Global.BOOT_COUNT` (null when unreadable).
 *
 * A negative elapsed value is impossible on a real device; it is reported as
 * "no reading" (null) so the Dart side applies the owner-approved D2-a
 * wall-clock fallback instead of a guessed value. An unknown or negative
 * boot count is reported as -1 (the Dart side then uses the 10 s drift rule).
 */
object MonotonicClock {
    const val KEY_ELAPSED_MS = "elapsedMs"
    const val KEY_BOOT_COUNT = "bootCount"
    const val UNKNOWN_BOOT_COUNT = -1

    fun reading(elapsedMs: Long, bootCount: Int?): Map<String, Any>? {
        if (elapsedMs < 0L) return null
        val boot = if (bootCount != null && bootCount >= 0) bootCount else UNKNOWN_BOOT_COUNT
        return mapOf(KEY_ELAPSED_MS to elapsedMs, KEY_BOOT_COUNT to boot)
    }
}
