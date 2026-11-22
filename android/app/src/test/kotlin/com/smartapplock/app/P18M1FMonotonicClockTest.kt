package com.smartapplock.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Phase 18 / M1F (F18-2). SIMULATED (JVM): the monotonic-clock channel reply.
 * Real `elapsedRealtime` / `BOOT_COUNT` behaviour (reboot, OEM) is DEVICE
 * PENDING.
 */
class P18M1FMonotonicClockTest {
    @Test fun knownBootCountIsReportedWithElapsed() {
        val r = MonotonicClock.reading(123_456L, 7)!!
        assertEquals(setOf("elapsedMs", "bootCount"), r.keys)
        assertEquals(123_456L, r["elapsedMs"] as Long)
        assertEquals(7, r["bootCount"] as Int)
    }

    @Test fun unknownOrNegativeBootCountIsMinusOne() {
        assertEquals(-1, MonotonicClock.reading(5L, null)!!["bootCount"])
        assertEquals(-1, MonotonicClock.reading(5L, -3)!!["bootCount"])
        assertEquals(0, MonotonicClock.reading(0L, 0)!!["bootCount"])
    }

    @Test fun negativeElapsedIsNoReadingNeverAGuess() {
        assertNull(MonotonicClock.reading(-1L, 4))
    }
}
