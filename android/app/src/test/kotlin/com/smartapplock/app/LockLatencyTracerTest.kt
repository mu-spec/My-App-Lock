package com.smartapplock.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 17 / M1 — LockLatencyTracer (pure JVM, fake monotonic clock).
 *
 * SIMULATED: these tests check ordering, attribution, bounding, privacy and
 * the percentile maths of the observational tracer. The durations below are
 * fake-clock values, not device measurements.
 */
class LockLatencyTracerTest {
    private var now = 0L
    private val ms = 1_000_000L
    private fun tracer(capacity: Int = 128) = LockLatencyTracer(clockNs = { now }, capacity = capacity)

    @Suppress("UNCHECKED_CAST")
    private fun group(report: Map<String, Any?>, name: String): Map<String, Any?>? =
        (report["groups"] as Map<String, Any?>)[name] as Map<String, Any?>?

    @Suppress("UNCHECKED_CAST")
    private fun anomalies(report: Map<String, Any?>): Map<String, Int> =
        report["anomalies"] as Map<String, Int>

    /** One full foreground lock: detect 0, policy 2, shield 5, activity 6, ready 300 (ms). */
    private fun fullAttempt(t: LockLatencyTracer, generation: Long, base: Long, readyAfterMs: Long = 300) {
        now = base
        val detected = now
        now = base + 2 * ms
        val start = t.start(LatencyTrigger.FOREGROUND, detected)
        now = base + 5 * ms
        t.shieldShown(generation, true, start)
        now = base + 6 * ms
        t.activityRequested(generation, LatencyLaunchMode.TASK_TO_FRONT, true)
        now = base + readyAfterMs * ms
        t.challengeReady(generation)
    }

    @Test
    fun `full sequence records every stage in order`() {
        val t = tracer()
        fullAttempt(t, 7L, 1_000 * ms)
        val s = t.samples().single()
        assertEquals(LatencyOutcome.COMPLETE, s.outcome)
        assertEquals(LatencyTrigger.FOREGROUND, s.trigger)
        assertEquals(LatencyLaunchMode.TASK_TO_FRONT, s.launchMode)
        assertTrue(s.ordered)
        assertEquals(300 * ms, s.endToEndNs)
        assertEquals(2 * ms, s.detectToPolicyNs)
        assertEquals(3 * ms, s.policyToShieldNs)
        assertEquals(1 * ms, s.shieldToActivityNs)
        assertEquals(294 * ms, s.activityToReadyNs)
        assertEquals(295 * ms, s.shieldToReadyNs)
        assertEquals(0, t.openCount())
    }

    @Test
    fun `ready for an unknown generation is counted and creates nothing`() {
        val t = tracer()
        t.challengeReady(99L)
        assertTrue(t.samples().isEmpty())
        assertEquals(1, anomalies(t.report())["readyUnknownGeneration"])
    }

    @Test
    fun `missing activity stage still completes but is reported without that span`() {
        val t = tracer()
        now = 0
        t.shieldShown(1L, true, LatencyStart(LatencyTrigger.FOREGROUND, 0, 0))
        now = 50 * ms
        t.challengeReady(1L)
        val s = t.samples().single()
        assertNull(s.activityNs)
        assertNull(s.shieldToActivityNs)
        assertEquals(50 * ms, s.endToEndNs)
        assertEquals(LatencyLaunchMode.UNKNOWN, s.launchMode)
    }

    @Test
    fun `failed shield or refused launch never opens or advances an attempt`() {
        val t = tracer()
        t.shieldShown(1L, false, LatencyStart(LatencyTrigger.FOREGROUND, 0, 0))
        assertEquals(0, t.openCount())
        t.shieldShown(2L, true, null)
        t.activityRequested(2L, LatencyLaunchMode.COLD_START, false)
        t.activityRequested(3L, LatencyLaunchMode.COLD_START, true)
        val a = anomalies(t.report())
        assertEquals(1, a["shieldFailures"])
        assertEquals(1, a["launchFailures"])
        assertEquals(1, a["stagesWithoutAttempt"])
        now = 10 * ms
        t.challengeReady(2L)
        assertNull(t.samples().single().activityNs)
    }

    @Test
    fun `a newer generation supersedes the older open attempt`() {
        val t = tracer()
        t.shieldShown(1L, true, LatencyStart(LatencyTrigger.FOREGROUND, 0, 0))
        now = 10 * ms
        t.shieldShown(2L, true, LatencyStart(LatencyTrigger.FOREGROUND, now, now))
        now = 20 * ms
        t.challengeReady(1L) // stale ready: the old attempt is already closed
        t.challengeReady(2L)
        val samples = t.samples()
        assertEquals(listOf(LatencyOutcome.SUPERSEDED, LatencyOutcome.COMPLETE), samples.map { it.outcome })
        assertEquals(10 * ms, samples[1].endToEndNs)
        assertEquals(1, anomalies(t.report())["readyUnknownGeneration"])
    }

    @Test
    fun `duplicate foreground shield keeps the first detection (no flattering rebase)`() {
        val t = tracer()
        t.shieldShown(1L, true, LatencyStart(LatencyTrigger.FOREGROUND, 0, 0))
        now = 100 * ms
        t.shieldShown(1L, true, LatencyStart(LatencyTrigger.FOREGROUND, now, now))
        now = 400 * ms
        t.challengeReady(1L)
        assertEquals(400 * ms, t.samples().single().endToEndNs)
        assertEquals(1, anomalies(t.report())["duplicateStages"])
        assertEquals(0, anomalies(t.report())["rebased"])
    }

    @Test
    fun `wake trigger rebases the unready generation so keyguard time is excluded`() {
        val t = tracer()
        t.shieldShown(5L, true, LatencyStart(LatencyTrigger.SCREEN_ON, 0, 0))
        // Behind keyguard for 8 s, then USER_PRESENT re-raises the same generation.
        now = 8_000 * ms
        t.shieldShown(5L, true, LatencyStart(LatencyTrigger.USER_PRESENT, now, now))
        now = 8_120 * ms
        t.challengeReady(5L)
        val s = t.samples().single()
        assertEquals(LatencyTrigger.USER_PRESENT, s.trigger)
        assertEquals(120 * ms, s.endToEndNs)
        assertEquals(1, anomalies(t.report())["rebased"])
    }

    @Test
    fun `out-of-order stamps are flagged and excluded from statistics`() {
        val t = tracer()
        now = 5 * ms
        // detection stamped AFTER the shield (clock misuse) must not count.
        t.shieldShown(1L, true, LatencyStart(LatencyTrigger.FOREGROUND, 9 * ms, 9 * ms))
        now = 20 * ms
        t.challengeReady(1L)
        assertFalse(t.samples().single().ordered)
        val r = t.report()
        assertEquals(0, r["complete"])
        assertEquals(1, anomalies(r)["outOfOrder"])
    }

    @Test
    fun `open attempts expire and are reported as expired, never complete`() {
        val t = tracer()
        t.shieldShown(1L, true, LatencyStart(LatencyTrigger.FOREGROUND, 0, 0))
        now = 121_000 * ms
        val r = t.report()
        assertEquals(1, r["expired"])
        assertEquals(0, r["complete"])
        t.challengeReady(1L)
        assertEquals(1, anomalies(t.report())["readyUnknownGeneration"])
    }

    @Test
    fun `finished samples are bounded`() {
        val t = tracer(capacity = 4)
        for (g in 1L..10L) fullAttempt(t, g, g * 1_000 * ms)
        assertEquals(4, t.samples().size)
    }

    @Test
    fun `a throwing clock never propagates into enforcement`() {
        val t = LockLatencyTracer(clockNs = { throw IllegalStateException("clock") })
        assertEquals(0L, t.nowNs())
        val start = t.start(LatencyTrigger.FOREGROUND, 0L)
        t.shieldShown(1L, true, start)
        t.activityRequested(1L, LatencyLaunchMode.RESUMED, true)
        t.wakePersisted(1L, 5L)
        t.challengeReady(1L)
        assertNotNull(t.report())
    }

    @Test
    fun `nearest-rank percentiles and minimum sample counts`() {
        val sorted = (1L..20L).map { it * 1000 }
        assertEquals(10_000L, LockLatencyTracer.percentile(sorted, 50))
        assertEquals(19_000L, LockLatencyTracer.percentile(sorted, 95))
        assertEquals(1_000L, LockLatencyTracer.percentile(listOf(1_000L), 95))
        val few = LockLatencyTracer.stats(listOf(3_000L, 1_000L, 2_000L, 4_000L))
        assertEquals(4, few["n"])
        assertNull(few["p50Us"])
        assertNull(few["p95Us"])
        assertEquals(4L, few["maxUs"])
        val five = LockLatencyTracer.stats(listOf(5_000L, 1_000L, 2_000L, 4_000L, 3_000L))
        assertEquals(3L, five["p50Us"])
        assertNull(five["p95Us"])
        val twenty = LockLatencyTracer.stats(sorted)
        assertEquals(10L, twenty["p50Us"])
        assertEquals(19L, twenty["p95Us"])
        assertEquals(20L, twenty["maxUs"])
    }

    @Test
    fun `report groups by trigger and launch mode with P50 P95 max`() {
        val t = tracer()
        for (g in 1L..20L) fullAttempt(t, g, g * 10_000 * ms, readyAfterMs = 100 + g * 10)
        val r = t.report()
        assertEquals(20, r["complete"])
        @Suppress("UNCHECKED_CAST")
        val e2e = group(r, "all")!!["endToEnd"] as Map<String, Any?>
        assertEquals(20, e2e["n"])
        assertEquals(200_000L, e2e["p50Us"]) // rank 10 -> 100 + 100 ms
        assertEquals(290_000L, e2e["p95Us"]) // rank 19 -> 100 + 190 ms
        assertEquals(300_000L, e2e["maxUs"])
        assertNotNull(group(r, "trigger.FOREGROUND"))
        assertNotNull(group(r, "launch.TASK_TO_FRONT"))
        assertNull(group(r, "launch.COLD_START"))
    }

    @Test
    fun `rendered report holds durations and enum labels only`() {
        val t = tracer()
        fullAttempt(t, 41L, 1_000 * ms)
        val text = LockLatencyTracer.render(t.report())
        assertTrue(text.startsWith("{\"schema\":1"))
        assertFalse("generation must not be exported", text.contains("41"))
        assertFalse(text.contains("com."))
        assertFalse(text.contains("package"))
        assertTrue(text.contains("\"endToEnd\""))
        // The latest sample is exported as labels + microsecond spans only.
        assertTrue(text.contains("\"last\":{\"trigger\":\"FOREGROUND\",\"launch\":\"TASK_TO_FRONT\""))
        assertTrue(text.contains("\"endToEndUs\":300000"))
    }

    @Test
    fun `reset clears samples, open attempts and anomalies`() {
        val t = tracer()
        fullAttempt(t, 1L, 0)
        t.shieldShown(2L, true, null)
        t.challengeReady(77L)
        t.reset()
        val r = t.report()
        assertEquals(0, r["samples"])
        assertEquals(0, r["open"])
        assertEquals(0, anomalies(r)["readyUnknownGeneration"])
    }
}
