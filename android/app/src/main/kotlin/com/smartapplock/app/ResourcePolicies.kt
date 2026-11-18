package com.smartapplock.app

/**
 * Phase 17 / M2: pure (JVM-testable) resource policies. None of them takes
 * part in a lock, authorization, shield or challenge decision; each only
 * removes work that code analysis showed to be redundant.
 */

/**
 * R1. The watcher notification was rebuilt and re-posted on every Dart
 * heartbeat (every 2 s while the engine lives), although its only variable
 * part, the engine-health text, rarely changes. Every `notify()` is a
 * binder call into system_server, a SystemUI update and a callback into
 * every notification listener (including Smart App Lock's own).
 *
 * A post is made when the text changes (immediately, both directions), when
 * nothing has been posted by this service instance yet, or when the last
 * post is at least [maxAgeMs] old (a bounded refresh that keeps the previous
 * "re-shown after a dismissal" behaviour, now within [maxAgeMs] instead of
 * 2 s). Any clock anomaly posts. Not thread-safe by itself; the caller
 * serialises (WatcherService runs it on its own monitor).
 */
class ForegroundNotificationRefresher(
    private val maxAgeMs: Long = DEFAULT_MAX_AGE_MS,
) {
    private var lastText: String? = null
    private var lastPostElapsedMs: Long = Long.MIN_VALUE

    /** True when [text] must be posted now; a true answer is recorded as posted. */
    fun take(text: String, nowElapsedMs: Long): Boolean {
        val post = lastText == null ||
            lastText != text ||
            lastPostElapsedMs == Long.MIN_VALUE ||
            nowElapsedMs < lastPostElapsedMs ||
            nowElapsedMs - lastPostElapsedMs >= maxAgeMs
        if (post) markPosted(text, nowElapsedMs)
        return post
    }

    /** Records a post made elsewhere (startForeground in onStartCommand). */
    fun markPosted(text: String, nowElapsedMs: Long) {
        lastText = text
        lastPostElapsedMs = nowElapsedMs
    }

    companion object {
        const val DEFAULT_MAX_AGE_MS = 60_000L
    }
}

/**
 * R2. `ProtectionOverlayController.hide()` ran a full WindowManager relayout
 * of the full-screen shield window on every unprotected foreground report
 * (each Accessibility window event and, while UsageEvents still returns the
 * app, every 1 s poll), even when the shield was already in standby.
 *
 * The relayout may be skipped ONLY when the window is provably already in
 * the standby state the relayout would set: not showing, still attached,
 * view INVISIBLE and the standby layout values in place. Anything else
 * (showing, detached, unexpected values) takes the unchanged relayout path,
 * including its failure handling. This only applies to RELEASING an
 * already-released shield; [ProtectionOverlayController.show] is untouched.
 */
object ShieldStandbyPolicy {
    fun relayoutNeeded(
        showing: Boolean,
        attachedToWindow: Boolean,
        viewInvisible: Boolean,
        standbyLayoutInPlace: Boolean,
    ): Boolean = showing || !attachedToWindow || !viewInvisible || !standbyLayoutInPlace
}

/**
 * R3. The Accessibility EventChannel sink is held statically by
 * [AccessibilityLockService]. Flutter does not call `onCancel` when an
 * engine is destroyed (the Activity is finished or removed from Recents
 * while the foreground service keeps the process alive), so the static
 * field kept the dead engine's sink (and, through it, that engine's
 * messenger objects) reachable, and every later Accessibility event was
 * still encoded and sent to the detached engine.
 *
 * This slot remembers which owner (engine) installed the value. An owner
 * can only clear its OWN value: a late cancel or teardown of an older
 * engine never clears the sink of a newer engine. Native enforcement does
 * not use this sink at all.
 */
class OwnedSlot<T : Any> {
    @Volatile private var owner: Any? = null
    @Volatile var value: T? = null
        private set

    @Synchronized
    fun attach(newOwner: Any, newValue: T?) {
        owner = newOwner
        value = newValue
    }

    /** Clears the value only when [releasingOwner] installed it. */
    @Synchronized
    fun release(releasingOwner: Any): Boolean {
        if (owner !== releasingOwner) return false
        owner = null
        value = null
        return true
    }
}
