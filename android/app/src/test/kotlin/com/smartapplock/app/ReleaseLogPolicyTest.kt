package com.smartapplock.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Phase 13 / M3 (N-1): native diagnostics only in debuggable builds. */
class ReleaseLogPolicyTest {
    // android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE (1 shl 1).
    private val debuggable = 1 shl 1

    @Test
    fun releaseFlagsWithoutDebuggableNeverLog() {
        assertFalse(ReleaseLogPolicy.allows(0, debuggable))
        // Typical release flags: HAS_CODE | ALLOW_CLEAR_USER_DATA | ... but
        // never FLAG_DEBUGGABLE.
        assertFalse(ReleaseLogPolicy.allows(0x00000004 or 0x00000040, debuggable))
        assertFalse(ReleaseLogPolicy.allows(debuggable.inv(), debuggable))
    }

    @Test
    fun debuggableBuildLogs() {
        assertTrue(ReleaseLogPolicy.allows(debuggable, debuggable))
        assertTrue(ReleaseLogPolicy.allows(debuggable or 0x00000004, debuggable))
    }

    @Test
    fun unknownFlagsFailClosed() {
        assertFalse(ReleaseLogPolicy.allows(null, debuggable))
    }

    @Test
    fun invalidMaskFailsClosed() {
        assertFalse(ReleaseLogPolicy.allows(-1, 0))
        assertFalse(ReleaseLogPolicy.allows(0, 0))
    }
}
