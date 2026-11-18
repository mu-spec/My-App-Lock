package com.smartapplock.app

import android.os.SystemClock

/**
 * The process-wide tracer on SystemClock.elapsedRealtimeNanos (monotonic,
 * keeps counting in deep sleep). Lazily created, so JVM tests that never
 * touch it never call the Android clock.
 */
object LockLatency {
    val tracer: LockLatencyTracer by lazy {
        LockLatencyTracer(clockNs = { SystemClock.elapsedRealtimeNanos() })
    }

    fun nowNs(): Long = try {
        tracer.nowNs()
    } catch (_: Throwable) {
        0L
    }
}
