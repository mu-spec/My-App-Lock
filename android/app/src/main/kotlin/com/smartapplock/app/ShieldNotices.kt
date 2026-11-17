package com.smartapplock.app

/**
 * P13/M3 Batch 2 (owner-approved G7-H1 option 2): neutral copy shown ON the
 * native shield when Flutter reports that the credential state is
 * unreadable (secure storage unavailable / key not available). Equivalent
 * to the Flutter G-7 copy. It never mentions setup, reset, a new PIN or
 * clearing a lockout, and it is shown for KeyLost too (G7-KL-1: dedicated
 * key-loss wording is a pending owner decision).
 */
object ShieldNotices {
    const val STORAGE_UNAVAILABLE_MESSAGE =
        "Smart App Lock\nSecure storage is temporarily unavailable.\n" +
            "Your protected apps remain locked. Please try again."

    /** Text-only policy: the notice may be applied only to a visible shield. */
    fun mayApplyStorageNotice(shieldShowing: Boolean): Boolean = shieldShowing
}
