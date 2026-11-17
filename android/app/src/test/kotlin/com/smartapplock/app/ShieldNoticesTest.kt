package com.smartapplock.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** P13/M3 Batch 2 (G7-H1 option 2): neutral shield copy + text-only policy. JVM. */
class ShieldNoticesTest {
    @Test
    fun `SN-1 storage notice copy is neutral and applies only to a visible shield`() {
        val m = ShieldNotices.STORAGE_UNAVAILABLE_MESSAGE
        assertTrue(m.contains("Secure storage is temporarily unavailable."))
        assertTrue(m.contains("Your protected apps remain locked."))
        for (w in listOf("reset", "set up", "setup", "new pin", "clear", "unlock now", "disable")) {
            assertFalse(w, m.lowercase().contains(w))
        }
        assertTrue(ShieldNotices.mayApplyStorageNotice(true))
        assertFalse(ShieldNotices.mayApplyStorageNotice(false))
    }
}
