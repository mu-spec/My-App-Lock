package com.smartapplock.app

import com.smartapplock.app.NotificationPrivacyEngine.Posted
import com.smartapplock.app.NotificationPrivacyEngine.RemovalCause
import com.smartapplock.app.NotificationPrivacyPolicy.Mode
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Phase 17 / M3: stress, recovery and fail-closed invariants of the pure
 * native state (JVM, deterministic, bounded iteration counts).
 *
 * SIMULATED (evidence B): no Android process, service, listener or OEM
 * behaviour is exercised here. Counts are fixed so the run is reproducible.
 */
class P17M3StressRecoveryTest {
    private val locked = "com.example.locked"
    private val other = "com.example.other"
    private val launcher = "com.example.launcher"
    private val CHALLENGE = ProtectionAccessState.Decision.CHALLENGE
    private val ALLOW = ProtectionAccessState.Decision.ALLOW

    @Before
    fun reset() {
        ProtectionAccessState.revokeAll()
        ProtectionRuntime.invalidateChallengeHandoff()
        ProtectionAccessState.setGracePeriod(0L)
        ProtectionAccessState.observeForeground(launcher, false, 0L)
    }

    @After
    fun tearDown() = reset()

    // -------------------------------------------------- ProtectionAccessState

    @Test
    fun repeatedLaunchAuthLeaveCyclesNeverCarryAGrantAcrossALeave() {
        var now = 1_000L
        repeat(1_000) {
            assertEquals("cycle $it: challenge before auth", CHALLENGE,
                ProtectionAccessState.observeForeground(locked, true, now++))
            ProtectionAccessState.authorize(locked, 120_000L, now++)
            assertEquals(ALLOW, ProtectionAccessState.observeForeground(locked, true, now++))
            ProtectionAccessState.observeForeground(launcher, false, now++)
            assertFalse("cycle $it: zero grace ends the grant",
                ProtectionAccessState.isAuthorized(locked))
        }
    }

    @Test
    fun rapidProtectedUnprotectedSwitchingWithoutAuthNeverAllows() {
        var now = 1L
        repeat(10_000) {
            val pkg = if (it % 3 == 0) other else locked
            val protectedPkg = pkg == locked
            val d = ProtectionAccessState.observeForeground(pkg, protectedPkg, now++)
            if (protectedPkg) assertEquals("event $it", CHALLENGE, d)
        }
        assertFalse(ProtectionAccessState.isAuthorized(locked))
    }

    @Test
    fun graceGrantNeverOutlivesTheGraceUnderRapidSwitching() {
        ProtectionAccessState.setGracePeriod(5_000L)
        var now = 10_000L
        ProtectionAccessState.authorize(locked, 600_000L, now)
        // Rapid in-grace switching keeps the grant (configured behaviour).
        repeat(500) {
            ProtectionAccessState.observeForeground(launcher, false, ++now)
            assertEquals(ALLOW, ProtectionAccessState.observeForeground(locked, true, ++now))
        }
        // One away period at or beyond the grace always ends it.
        ProtectionAccessState.observeForeground(launcher, false, ++now)
        now += 5_000L
        assertEquals(CHALLENGE, ProtectionAccessState.observeForeground(locked, true, now))
        repeat(100) {
            assertEquals(CHALLENGE, ProtectionAccessState.observeForeground(locked, true, ++now))
        }
    }

    @Test
    fun screenOffRevocationCyclesAndProcessLocalResetNeverGrant() {
        var now = 1L
        repeat(500) {
            ProtectionAccessState.authorize(locked, 120_000L, now++)
            ProtectionAccessState.authorize(other, 120_000L, now++)
            // WatcherService ACTION_SCREEN_OFF / onDestroy(INTERRUPTED) /
            // engine detach without a watcher: all call revokeAll().
            ProtectionAccessState.revokeAll()
            ProtectionRuntime.invalidateChallengeHandoff()
            assertFalse(ProtectionAccessState.isAuthorized(locked))
            assertFalse(ProtectionAccessState.isAuthorized(other))
            assertEquals(CHALLENGE, ProtectionAccessState.observeForeground(locked, true, now++))
            assertNull(ProtectionRuntime.readyChallenge())
        }
    }

    @Test
    fun unprotectReprotectCyclesNeverReviveAStaleGrant() {
        var now = 1L
        repeat(500) {
            ProtectionAccessState.authorize(locked, 600_000L, now++)
            ProtectionAccessState.retainProtectedPackages(setOf(other)) // unprotect
            assertFalse(ProtectionAccessState.isAuthorized(locked))
            // Re-protected: the old grant must not come back.
            assertEquals(CHALLENGE, ProtectionAccessState.observeForeground(locked, true, now++))
            ProtectionAccessState.observeForeground(launcher, false, now++)
        }
    }

    @Test
    fun teardownPolicyRevokesOnEveryInterruptedOrUnwatchedDetach() {
        repeat(200) {
            val enabled = it % 2 == 0
            val watcher = it % 3 == 0
            val action = WatcherTeardownPolicy.onDestroy(enabled)
            assertEquals(enabled, action.revokesAuthorizations)
            assertEquals(!enabled, action.disarmsOverlay)
            assertEquals(enabled && !watcher,
                WatcherTeardownPolicy.revokesOnEngineDetach(enabled, watcher))
        }
        assertTrue(WatcherTeardownPolicy.clearsLastErrorOnStart(LastErrorCode.WATCHER_INTERRUPTED))
        assertFalse(WatcherTeardownPolicy.clearsLastErrorOnStart(null))
    }

    // ------------------------------------- Accessibility interruption (fix)

    /**
     * P17/M3 defect A11Y-1 (static analysis, evidence C): an Accessibility
     * unbind/destroy left native grants in place. With the watcher's
     * UsageEvents poll unavailable, a leave and return during the outage is
     * unobserved; after the rebind the first report for the same package
     * saw previous == package and returned ALLOW on the stale grant.
     */
    @Test
    fun accessibilityDisconnectEndsGrantsSoAnUnobservedReturnIsChallenged() {
        var now = 1_000L
        ProtectionAccessState.authorize(locked, 600_000L, now)
        assertEquals(ALLOW, ProtectionAccessState.observeForeground(locked, true, ++now))
        // AccessibilityLockService.onUnbind / onDestroy (protection on).
        if (WatcherTeardownPolicy.revokesOnAccessibilityDisconnect(protectionEnabled = true)) {
            ProtectionAccessState.revokeAll()
        }
        // Outage: the user leaves and returns; nothing is reported.
        now += 30_000L
        // Rebind: the first report is the same package as before.
        assertEquals(CHALLENGE, ProtectionAccessState.observeForeground(locked, true, ++now))
        repeat(200) {
            ProtectionAccessState.authorize(locked, 600_000L, ++now)
            if (WatcherTeardownPolicy.revokesOnAccessibilityDisconnect(true)) {
                ProtectionAccessState.revokeAll()
            }
            assertEquals("cycle $it", CHALLENGE,
                ProtectionAccessState.observeForeground(locked, true, ++now))
        }
        // Protection off: nothing to protect, no behaviour change.
        assertFalse(WatcherTeardownPolicy.revokesOnAccessibilityDisconnect(false))
    }

    @Test
    fun accessibilityServiceRevokesOnBothDisconnectCallbacksOnly() {
        val dir = listOf(
            java.io.File("src/main/kotlin/com/smartapplock/app"),
            java.io.File("android/app/src/main/kotlin/com/smartapplock/app"),
        ).first { it.isDirectory }
        val src = java.io.File(dir, "AccessibilityLockService.kt").readText()
        fun section(start: String, end: String): String {
            val a = src.indexOf(start)
            assertTrue("missing $start", a >= 0)
            val b = src.indexOf(end, a)
            assertTrue("missing $end", b > a)
            return src.substring(a, b)
        }
        val unbind = section("override fun onUnbind(", "override fun onDestroy()")
        val destroy = section("override fun onDestroy()", "private fun revokeOnDisconnect()")
        val helper = section("private fun revokeOnDisconnect()", "companion object")
        for (body in listOf(unbind, destroy)) {
            assertTrue(body.contains("AccessibilityConnection.onDisconnected()"))
            assertTrue(body.contains("revokeOnDisconnect()"))
        }
        assertTrue(
            unbind.indexOf("revokeOnDisconnect()") < unbind.indexOf("return super.onUnbind(intent)"),
        )
        val policy = helper.indexOf("WatcherTeardownPolicy.revokesOnAccessibilityDisconnect(")
        val revoke = helper.indexOf("ProtectionAccessState.revokeAll()")
        assertTrue(policy >= 0)
        assertTrue(revoke > policy)
        assertTrue(helper.contains("ProtectionStateStore.isEnabled(this)"))
        // Revocation only: the ticket, hand-off and shield are untouched.
        for (body in listOf(unbind, destroy, helper)) {
            for (forbidden in listOf("invalidateChallengeHandoff", "clearPendingChallenge",
                    "ProtectionOverlayController", "authorize(")) {
                assertFalse(forbidden, body.contains(forbidden))
            }
        }
        // The connect path never grants or revokes.
        val connected = section("override fun onServiceConnected()", "override fun onAccessibilityEvent(")
        assertFalse(connected.contains("authorize("))
    }

    // ------------------------------------------- hand-off / latch concurrency

    @Test
    fun concurrentHandoffConsumptionSucceedsExactlyOncePerTicket() {
        val pool = Executors.newFixedThreadPool(8)
        try {
            repeat(200) { gen ->
                val ticket = ProtectionStateStore.PendingChallenge(locked, gen.toLong() + 1)
                ProtectionRuntime.markChallengeReady(ticket)
                val wins = AtomicInteger()
                val start = CountDownLatch(1)
                val done = CountDownLatch(8)
                repeat(8) {
                    pool.execute {
                        start.await()
                        if (ProtectionRuntime.consumeChallengeHandoff(locked, ticket.generation)) {
                            wins.incrementAndGet()
                        }
                        done.countDown()
                    }
                }
                start.countDown()
                assertTrue(done.await(5, TimeUnit.SECONDS))
                assertEquals("ticket $gen", 1, wins.get())
                // A stale generation can never consume a newer ticket.
                ProtectionRuntime.markChallengeReady(
                    ProtectionStateStore.PendingChallenge(locked, ticket.generation + 1))
                assertFalse(ProtectionRuntime.consumeChallengeHandoff(locked, ticket.generation))
                ProtectionRuntime.invalidateChallengeHandoff()
            }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun oneShotRestartLatchAdmitsExactlyOneOfManyConcurrentStarts() {
        val pool = Executors.newFixedThreadPool(8)
        try {
            repeat(200) { round ->
                val latch = OneShotLatch()
                val wins = AtomicInteger()
                val start = CountDownLatch(1)
                val done = CountDownLatch(16)
                repeat(16) {
                    pool.execute {
                        start.await()
                        if (latch.tryAcquire()) wins.incrementAndGet()
                        done.countDown()
                    }
                }
                start.countDown()
                assertTrue(done.await(5, TimeUnit.SECONDS))
                assertEquals("round $round", 1, wins.get())
                assertFalse(latch.tryAcquire())
            }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun safeExitFromAnOlderTicketNeverConfirmsAgainstANewerTicket() {
        val gate = SafeExitGate()
        val home = "com.example.home"
        repeat(500) {
            val old = ProtectionStateStore.PendingChallenge(locked, 2L * it + 1)
            val newer = ProtectionStateStore.PendingChallenge(locked, 2L * it + 2)
            assertTrue(gate.begin(SafeExitRequest(old, home)))
            assertFalse("idempotent", gate.begin(SafeExitRequest(old, home)))
            val r = if (it % 2 == 0) gate.resolveForeground(newer, home) else gate.resolveTimeout(newer)
            assertEquals(SafeExitResolution.STALE, r)
            assertFalse(gate.isInProgress())
            assertEquals(SafeExitResolution.NONE, gate.resolveTimeout(newer))
        }
    }

    // ------------------------------------------ notification listener cycles

    private val own = "com.smartapplock.app"
    private val bank = "com.bank.app"
    private val salt = ByteArray(16) { it.toByte() }

    private class Port(val state: NotificationPrivacyPolicy.State, val salt: ByteArray) :
        NotificationPrivacyEngine.Port {
        val cancelled = mutableListOf<String>()
        val posted = mutableListOf<NotificationPrivacyEngine.Placeholder>()
        override fun state() = state
        override fun placeholderTag(packageName: String) =
            NotificationPrivacyEngine.placeholderTag(salt, packageName)
        override fun appLabel(packageName: String) = "Bank"
        override fun canPostPlaceholders(mode: Mode) = true
        override fun cancelSource(key: String): Boolean { cancelled += key; return true }
        override fun postPlaceholder(placeholder: NotificationPrivacyEngine.Placeholder): Boolean {
            posted += placeholder
            return true
        }
    }

    private fun port() = Port(
        NotificationPrivacyPolicy.State(own, true, setOf(bank), mapOf(bank to Mode.MAXIMUM), false),
        salt,
    )

    private fun original(i: Int) = Posted("0|$bank|$i|null|10123", bank, 0, true, null)

    @Test
    fun listenerReconnectCyclesNeverDuplicateLeakOrGrowState() {
        val port = port()
        val engine = NotificationPrivacyEngine(port)
        val tag = NotificationPrivacyEngine.placeholderTag(salt, bank)
        var placeholderVisible = false
        repeat(300) { cycle ->
            val active = mutableListOf<Posted>()
            if (placeholderVisible) active += Posted("ph", own, 0, true, tag)
            val postsBefore = port.posted.size
            engine.onConnected(active)
            assertTrue(engine.isConnected)
            // Reconnect re-renders the existing placeholder in place only.
            assertEquals(if (placeholderVisible) 1 else 0, port.posted.size - postsBefore)
            val p = original(cycle)
            engine.onPosted(p)
            assertEquals(p.key, port.cancelled.last())
            engine.onRemoved(p, RemovalCause.LISTENER)
            assertEquals(tag, port.posted.last().tag)
            placeholderVisible = true
            // A second original while the placeholder is shown: no duplicate.
            val q = original(10_000 + cycle)
            val beforeDup = port.posted.size
            engine.onPosted(q)
            engine.onRemoved(q, RemovalCause.LISTENER)
            assertEquals(beforeDup, port.posted.size)
            // Interruption: everything is dropped; callbacks are ignored.
            engine.onDisconnected()
            assertFalse(engine.isConnected)
            assertEquals(0, engine.pendingCount)
            assertTrue(engine.shownModes().isEmpty())
            val ignoredCancel = port.cancelled.size
            val ignoredPost = port.posted.size
            engine.onPosted(original(20_000 + cycle))
            engine.onRemoved(p, RemovalCause.LISTENER)
            assertEquals(ignoredCancel, port.cancelled.size)
            assertEquals(ignoredPost, port.posted.size)
        }
        // Every placeholder ever posted used the single per-app tag.
        assertTrue(port.posted.all { it.tag == tag && it.sourcePackage == bank })
    }

    @Test
    fun originalPostedDuringAnInterruptionIsHiddenOnReconnectSweep() {
        val port = port()
        val engine = NotificationPrivacyEngine(port)
        repeat(200) { cycle ->
            engine.onDisconnected()
            val missed = original(cycle) // posted while the listener was down
            engine.onPosted(missed)
            assertFalse(port.cancelled.contains(missed.key))
            engine.onConnected(listOf(missed))
            assertEquals("cycle $cycle", missed.key, port.cancelled.last())
            assertEquals(1, engine.pendingCount)
            engine.onRemoved(missed, RemovalCause.LISTENER)
            assertEquals(0, engine.pendingCount)
        }
    }

    @Test
    fun unconfirmedCancellationFloodStaysBounded() {
        val port = port()
        val engine = NotificationPrivacyEngine(port)
        engine.onConnected(emptyList())
        repeat(5_000) { engine.onPosted(original(it)) }
        assertEquals(NotificationPrivacyEngine.MAX_PENDING, engine.pendingCount)
        assertEquals(5_000, port.cancelled.size) // every original was still hidden
        engine.onDisconnected()
        assertEquals(0, engine.pendingCount)
    }
}
