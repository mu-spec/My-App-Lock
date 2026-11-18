package com.smartapplock.app

/**
 * Phase 17 / M1 — lock latency measurement (observational only).
 *
 * Records, per challenge generation, when each stage of the protection
 * sequence happened on ONE monotonic clock:
 *
 *  1. DETECTED  a protected-app report / wake / restart signal reached native
 *  2. POLICY    the LOCK decision was made (before recovery started)
 *  3. SHIELD    the opaque native shield was shown
 *  4. ACTIVITY  the authentication Activity was requested
 *  5. READY     native accepted the rendered Flutter challenge (shield hidden)
 *
 * Contract:
 *  - Observational: every entry point is total (catches everything, returns
 *    Unit). Enforcement never reads it, waits for it or branches on it.
 *  - Privacy: no package names, credentials, window content or wall-clock
 *    times are accepted or stored. Only enums, the in-memory generation
 *    counter (never exported) and monotonic durations.
 *  - Bounded: at most [capacity] finished samples and [maxOpen] open ones.
 *  - Pure logic: the clock is injected, so tests run on the JVM.
 */
enum class LatencyTrigger { FOREGROUND, SCREEN_ON, USER_PRESENT, PROCESS_RESTART, UNATTRIBUTED }

enum class LatencyLaunchMode { RESUMED, TASK_TO_FRONT, COLD_START, UNKNOWN }

enum class LatencyOutcome { COMPLETE, SUPERSEDED, EXPIRED }

/** Stages 1+2 of one recovery attempt, captured by the caller. */
data class LatencyStart(
    val trigger: LatencyTrigger,
    val detectedNs: Long,
    val policyNs: Long,
)

class LockLatencyTracer(
    private val clockNs: () -> Long,
    private val capacity: Int = 128,
    private val maxOpen: Int = 8,
    private val expireAfterNs: Long = 120_000_000_000L,
) {
    /** One finished measurement. Stamps share the injected clock. */
    data class Sample(
        val trigger: LatencyTrigger,
        val launchMode: LatencyLaunchMode,
        val outcome: LatencyOutcome,
        val detectedNs: Long?,
        val policyNs: Long?,
        val shieldNs: Long,
        val activityNs: Long?,
        val readyNs: Long?,
        val wakePersistNs: Long?,
        val ordered: Boolean,
    ) {
        /** Detection-to-challenge-ready (null without a detection stamp). */
        val endToEndNs: Long? get() = span(detectedNs, readyNs)
        val shieldToReadyNs: Long? get() = span(shieldNs, readyNs)
        val detectToPolicyNs: Long? get() = span(detectedNs, policyNs)
        val policyToShieldNs: Long? get() = span(policyNs, shieldNs)
        val shieldToActivityNs: Long? get() = span(shieldNs, activityNs)
        val activityToReadyNs: Long? get() = span(activityNs, readyNs)
    }

    private class Open(
        val generation: Long,
        val start: LatencyStart?,
        val shieldNs: Long,
    ) {
        var activityNs: Long? = null
        var launchMode: LatencyLaunchMode = LatencyLaunchMode.UNKNOWN
        var wakePersistNs: Long? = null
    }

    private val open = LinkedHashMap<Long, Open>()
    private val finished = ArrayDeque<Sample>()

    private var duplicateStages = 0
    private var rebased = 0
    private var stagesWithoutAttempt = 0
    private var readyUnknownGeneration = 0
    private var shieldFailures = 0
    private var launchFailures = 0
    private var outOfOrder = 0
    private var internalErrors = 0

    /** The clock, or 0 if it throws (never propagates). */
    fun nowNs(): Long = try {
        clockNs()
    } catch (_: Throwable) {
        0L
    }

    /** Builds a start whose POLICY stamp is now. Never throws. */
    fun start(trigger: LatencyTrigger, detectedNs: Long): LatencyStart =
        LatencyStart(trigger, detectedNs, nowNs())

    /**
     * Stage 3 for [generation]. The first shield for a generation opens the
     * attempt; a later shield for the same generation is a duplicate unless
     * it carries a wake start (SCREEN_ON / USER_PRESENT), which rebases the
     * still-unready attempt so keyguard/sleep time is not counted.
     */
    @Synchronized
    fun shieldShown(generation: Long, shown: Boolean, start: LatencyStart?) = guard {
        val now = nowNs()
        expireLocked(now)
        if (!shown) {
            shieldFailures++
            return@guard
        }
        val existing = open[generation]
        if (existing != null) {
            if (start != null && isWake(start.trigger)) {
                open[generation] = Open(generation, start, now)
                rebased++
            } else {
                duplicateStages++
            }
            return@guard
        }
        // A new generation supersedes every older open attempt.
        for (attempt in open.values.toList()) {
            finishLocked(attempt, null, LatencyOutcome.SUPERSEDED)
        }
        open[generation] = Open(generation, start, now)
        while (open.size > maxOpen) {
            finishLocked(open.values.first(), null, LatencyOutcome.EXPIRED)
        }
    }

    /** Stage 4. [launched] false means Android refused the hand-off. */
    @Synchronized
    fun activityRequested(generation: Long, mode: LatencyLaunchMode, launched: Boolean) = guard {
        val now = nowNs()
        val attempt = open[generation]
        if (attempt == null) {
            stagesWithoutAttempt++
            return@guard
        }
        if (!launched) {
            launchFailures++
            return@guard
        }
        if (attempt.activityNs != null) {
            duplicateStages++
            return@guard
        }
        attempt.activityNs = now
        attempt.launchMode = mode
    }

    /** Auxiliary: duration of the synchronous wake-identity write. */
    @Synchronized
    fun wakePersisted(generation: Long, durationNs: Long) = guard {
        val attempt = open[generation] ?: return@guard
        if (attempt.wakePersistNs == null && durationNs >= 0L) attempt.wakePersistNs = durationNs
    }

    /** Stage 5: native accepted the rendered challenge for [generation]. */
    @Synchronized
    fun challengeReady(generation: Long) = guard {
        val now = nowNs()
        val attempt = open[generation]
        if (attempt == null) {
            readyUnknownGeneration++
            return@guard
        }
        finishLocked(attempt, now, LatencyOutcome.COMPLETE)
    }

    /** Finished samples, oldest first (a copy). */
    @Synchronized
    fun samples(): List<Sample> = try {
        expireLocked(nowNs())
        finished.toList()
    } catch (_: Throwable) {
        emptyList()
    }

    @Synchronized
    fun openCount(): Int = open.size

    @Synchronized
    fun reset() = guard {
        open.clear()
        finished.clear()
        duplicateStages = 0
        rebased = 0
        stagesWithoutAttempt = 0
        readyUnknownGeneration = 0
        shieldFailures = 0
        launchFailures = 0
        outOfOrder = 0
        internalErrors = 0
    }

    /**
     * Privacy-safe aggregate for QA export: counts and microsecond durations
     * only. Nearest-rank percentiles; P50 needs [MIN_SAMPLES_P50] and P95
     * [MIN_SAMPLES_P95] samples, otherwise they are reported as null.
     * Out-of-order samples are counted but excluded from the statistics.
     */
    @Synchronized
    fun report(): Map<String, Any?> = try {
        expireLocked(nowNs())
        val all = finished.toList()
        val complete = all.filter { it.outcome == LatencyOutcome.COMPLETE && it.ordered }
        val groups = LinkedHashMap<String, Any?>()
        groups["all"] = groupStats(complete)
        for (t in LatencyTrigger.values()) {
            val g = complete.filter { it.trigger == t }
            if (g.isNotEmpty()) groups["trigger." + t.name] = groupStats(g)
        }
        for (m in LatencyLaunchMode.values()) {
            val g = complete.filter { it.launchMode == m }
            if (g.isNotEmpty()) groups["launch." + m.name] = groupStats(g)
        }
        linkedMapOf(
            "schema" to 1,
            "clock" to "monotonic",
            "samples" to all.size,
            "complete" to complete.size,
            "superseded" to all.count { it.outcome == LatencyOutcome.SUPERSEDED },
            "expired" to all.count { it.outcome == LatencyOutcome.EXPIRED },
            "open" to open.size,
            "anomalies" to linkedMapOf(
                "duplicateStages" to duplicateStages,
                "rebased" to rebased,
                "stagesWithoutAttempt" to stagesWithoutAttempt,
                "readyUnknownGeneration" to readyUnknownGeneration,
                "shieldFailures" to shieldFailures,
                "launchFailures" to launchFailures,
                "outOfOrder" to outOfOrder,
                "internalErrors" to internalErrors,
            ),
            "groups" to groups,
            "last" to all.lastOrNull()?.let { describe(it) },
        )
    } catch (_: Throwable) {
        mapOf("schema" to 1, "error" to true)
    }

    /** The most recent sample's spans in microseconds (labels + durations). */
    private fun describe(s: Sample): Map<String, Any?> = linkedMapOf(
        "trigger" to s.trigger.name,
        "launch" to s.launchMode.name,
        "outcome" to s.outcome.name,
        "ordered" to s.ordered,
        "endToEndUs" to s.endToEndNs?.div(1000),
        "detectToPolicyUs" to s.detectToPolicyNs?.div(1000),
        "policyToShieldUs" to s.policyToShieldNs?.div(1000),
        "shieldToActivityUs" to s.shieldToActivityNs?.div(1000),
        "activityToReadyUs" to s.activityToReadyNs?.div(1000),
        "shieldToReadyUs" to s.shieldToReadyNs?.div(1000),
        "wakePersistUs" to s.wakePersistNs?.div(1000),
    )

    private fun groupStats(samples: List<Sample>): Map<String, Any?> = linkedMapOf(
        "n" to samples.size,
        "endToEnd" to stats(samples.mapNotNull { it.endToEndNs }),
        "shieldToReady" to stats(samples.mapNotNull { it.shieldToReadyNs }),
        "detectToPolicy" to stats(samples.mapNotNull { it.detectToPolicyNs }),
        "policyToShield" to stats(samples.mapNotNull { it.policyToShieldNs }),
        "shieldToActivity" to stats(samples.mapNotNull { it.shieldToActivityNs }),
        "activityToReady" to stats(samples.mapNotNull { it.activityToReadyNs }),
        "wakePersist" to stats(samples.mapNotNull { it.wakePersistNs }),
    )

    private fun finishLocked(attempt: Open, readyNs: Long?, outcome: LatencyOutcome) {
        open.remove(attempt.generation)
        val stamps = listOfNotNull(
            attempt.start?.detectedNs,
            attempt.start?.policyNs,
            attempt.shieldNs,
            attempt.activityNs,
            readyNs,
        )
        val ordered = stamps.zipWithNext().all { (a, b) -> a <= b }
        if (!ordered) outOfOrder++
        finished.addLast(
            Sample(
                trigger = attempt.start?.trigger ?: LatencyTrigger.UNATTRIBUTED,
                launchMode = attempt.launchMode,
                outcome = outcome,
                detectedNs = attempt.start?.detectedNs,
                policyNs = attempt.start?.policyNs,
                shieldNs = attempt.shieldNs,
                activityNs = attempt.activityNs,
                readyNs = readyNs,
                wakePersistNs = attempt.wakePersistNs,
                ordered = ordered,
            ),
        )
        while (finished.size > capacity) finished.removeFirst()
    }

    private fun expireLocked(now: Long) {
        val stale = open.values.filter { now - it.shieldNs > expireAfterNs }
        for (attempt in stale) finishLocked(attempt, null, LatencyOutcome.EXPIRED)
    }

    private inline fun guard(block: () -> Unit) {
        try {
            block()
        } catch (_: Throwable) {
            internalErrors++
        }
    }

    companion object {
        const val MIN_SAMPLES_P50 = 5
        const val MIN_SAMPLES_P95 = 20

        private fun isWake(trigger: LatencyTrigger): Boolean =
            trigger == LatencyTrigger.SCREEN_ON || trigger == LatencyTrigger.USER_PRESENT

        private fun span(from: Long?, to: Long?): Long? =
            if (from == null || to == null || to < from) null else to - from

        /** Nearest-rank percentile of [sorted] (ascending, non-empty). */
        fun percentile(sorted: List<Long>, p: Int): Long {
            val rank = Math.ceil(p / 100.0 * sorted.size).toInt().coerceIn(1, sorted.size)
            return sorted[rank - 1]
        }

        /** Compact JSON rendering of [report] (keys are fixed identifiers). */
        fun render(value: Any?): String = when (value) {
            null -> "null"
            is Map<*, *> -> value.entries.joinToString(",", "{", "}") {
                "\"" + it.key.toString() + "\":" + render(it.value)
            }
            is Boolean, is Number -> value.toString()
            else -> "\"" + value.toString().replace("\\", "\\\\").replace("\"", "\\\"") + "\""
        }

        /** {n, p50Us, p95Us, maxUs}; percentiles null below their minimum n. */
        fun stats(valuesNs: List<Long>): Map<String, Any?> {
            val sorted = valuesNs.sorted()
            val n = sorted.size
            return linkedMapOf(
                "n" to n,
                "p50Us" to if (n >= MIN_SAMPLES_P50) percentile(sorted, 50) / 1000 else null,
                "p95Us" to if (n >= MIN_SAMPLES_P95) percentile(sorted, 95) / 1000 else null,
                "maxUs" to if (n >= 1) sorted.last() / 1000 else null,
            )
        }
    }
}
