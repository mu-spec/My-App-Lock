package com.smartapplock.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 17 / M2: resource policies (R1-R3). The "simulated" tests count
 * OPERATIONS in a modelled timeline (category B evidence). They are not
 * device RAM/CPU/battery measurements.
 */
class ResourcePoliciesTest {
    private val active = "Protection engine active"
    private val recovery = "Protection recovery active"

    // -- R1: notification refresh ------------------------------------------

    @Test
    fun `first refresh of a fresh instance always posts`() {
        assertTrue(ForegroundNotificationRefresher().take(active, 0L))
    }

    @Test
    fun `unchanged text is not re-posted inside the refresh window`() {
        val r = ForegroundNotificationRefresher(maxAgeMs = 60_000L)
        r.markPosted(active, 1_000L)
        assertFalse(r.take(active, 3_000L))
        assertFalse(r.take(active, 60_999L))
        assertTrue(r.take(active, 61_000L))
        assertFalse(r.take(active, 63_000L))
    }

    @Test
    fun `a health text change posts immediately in both directions`() {
        val r = ForegroundNotificationRefresher(maxAgeMs = 60_000L)
        r.markPosted(active, 0L)
        assertTrue(r.take(recovery, 1L))
        assertFalse(r.take(recovery, 2L))
        assertTrue(r.take(active, 3L))
    }

    @Test
    fun `a positive answer is recorded, a negative one is not`() {
        val r = ForegroundNotificationRefresher(maxAgeMs = 10L)
        assertTrue(r.take(active, 100L))
        assertFalse(r.take(active, 105L))
        // Not recorded at 105: the window still counts from 100.
        assertTrue(r.take(active, 110L))
    }

    @Test
    fun `a clock going backwards posts (fail toward the old behaviour)`() {
        val r = ForegroundNotificationRefresher()
        r.markPosted(active, 50_000L)
        assertTrue(r.take(active, 10_000L))
    }

    @Test
    fun `SIMULATED 10 min of 2 s heartbeats posts 10 instead of 300`() {
        val r = ForegroundNotificationRefresher()
        r.markPosted(active, 0L) // startForeground
        var baseline = 0
        var optimized = 0
        var t = 2_000L
        while (t <= 600_000L) {
            baseline++ // old code: notify() on every heartbeat
            if (r.take(active, t)) optimized++
            t += 2_000L
        }
        assertEquals(300, baseline)
        assertEquals(10, optimized)
    }

    @Test
    fun `SIMULATED engine loss is still shown at once while heartbeats are quiet`() {
        val r = ForegroundNotificationRefresher()
        r.markPosted(active, 0L)
        for (t in 2_000L..20_000L step 2_000L) r.take(active, t)
        // markEngineUnavailable -> recovery text: must post immediately.
        assertTrue(r.take(recovery, 21_000L))
        // Heartbeats resume -> active text: posted immediately again.
        assertTrue(r.take(active, 23_000L))
    }

    // -- R2: shield standby relayout ---------------------------------------

    @Test
    fun `relayout is skipped only for an attached invisible standby shield`() {
        assertFalse(
            ShieldStandbyPolicy.relayoutNeeded(
                showing = false,
                attachedToWindow = true,
                viewInvisible = true,
                standbyLayoutInPlace = true,
            ),
        )
    }

    @Test
    fun `every other state keeps the relayout path`() {
        for (showing in listOf(false, true)) {
            for (attached in listOf(false, true)) {
                for (invisible in listOf(false, true)) {
                    for (standby in listOf(false, true)) {
                        val skip = !showing && attached && invisible && standby
                        assertEquals(
                            "showing=$showing attached=$attached invisible=$invisible standby=$standby",
                            !skip,
                            ShieldStandbyPolicy.relayoutNeeded(showing, attached, invisible, standby),
                        )
                    }
                }
            }
        }
    }

    @Test
    fun `a showing shield is always relaid out on hide (release is never skipped)`() {
        assertTrue(ShieldStandbyPolicy.relayoutNeeded(true, true, true, true))
    }

    @Test
    fun `SIMULATED 60 s in an unprotected app no longer relays out the hidden shield`() {
        // Modelled reports while the shield is in standby: one UsageEvents
        // poll per second for the 60 s lookback plus 20 Accessibility events.
        val reports = 60 + 20
        var baseline = 0
        var optimized = 0
        var showing = false
        repeat(reports) {
            baseline++ // old hide(): updateViewLayout on every report
            if (ShieldStandbyPolicy.relayoutNeeded(showing, true, !showing, !showing)) {
                optimized++
                showing = false
            }
        }
        assertEquals(80, baseline)
        assertEquals(0, optimized)
        // A real release from a showing shield is still exactly one relayout.
        showing = true
        val release = ShieldStandbyPolicy.relayoutNeeded(showing, true, false, false)
        assertTrue(release)
    }

    // -- R3: owner-checked Accessibility sink ------------------------------

    @Test
    fun `the owner that installed the sink can release it`() {
        val slot = OwnedSlot<String>()
        val engine = Any()
        slot.attach(engine, "sink-1")
        assertEquals("sink-1", slot.value)
        assertTrue(slot.release(engine))
        assertNull(slot.value)
    }

    @Test
    fun `an older engine can never clear a newer engine's sink`() {
        val slot = OwnedSlot<String>()
        val oldEngine = Any()
        val newEngine = Any()
        slot.attach(oldEngine, "old")
        slot.attach(newEngine, "new")
        assertFalse(slot.release(oldEngine))
        assertSame("new", slot.value)
        assertTrue(slot.release(newEngine))
        assertNull(slot.value)
    }

    @Test
    fun `release uses identity, not equality`() {
        val slot = OwnedSlot<String>()
        slot.attach("engine", "sink")
        @Suppress("StringOperationCanBeSimplified")
        val equalButDifferent = String("engine".toCharArray())
        assertFalse(slot.release(equalButDifferent))
        assertEquals("sink", slot.value)
    }

    @Test
    fun `repeated release and unknown owners are harmless`() {
        val slot = OwnedSlot<String>()
        assertFalse(slot.release(Any()))
        val engine = Any()
        slot.attach(engine, "s")
        assertTrue(slot.release(engine))
        assertFalse(slot.release(engine))
        assertNull(slot.value)
    }

    @Test
    fun `SIMULATED 200 engine create-destroy cycles retain no dead sink`() {
        val slot = OwnedSlot<Any>()
        var retainedAfterTeardown = 0
        repeat(200) {
            val engine = Any()
            slot.attach(engine, Any())
            slot.release(engine) // cleanUpFlutterEngine
            if (slot.value != null) retainedAfterTeardown++
        }
        assertEquals(0, retainedAfterTeardown)
    }
}
