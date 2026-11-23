package com.smartapplock.app

import com.smartapplock.app.ProtectionAccessState.Decision.ALLOW
import com.smartapplock.app.ProtectionAccessState.Decision.CHALLENGE
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

/**
 * Phase 18 / M3 (M3-A, M3-D): native grant invariants across Accessibility
 * interruptions. SIMULATED (evidence B, JVM): drives the production
 * [ProtectionAccessState] and [WatcherTeardownPolicy] with an explicit
 * elapsed clock. Device behaviour (OEM unbind ordering, process death) is
 * physical-device QA.
 *
 *  AI-1 an expired grant is never revived by a reconnection: the first
 *       report after the outage is the same package and still challenges.
 *  AI-2 a protected-set change during an outage (removed, then re-added)
 *       never revives the old grant, with or without the A11Y-1 revocation.
 *  AI-3 a grace-period absence that spans an Accessibility disconnect
 *       challenges on return, even inside the grace window.
 *  AI-4 a grant never covers another package (no cross-app ALLOW), and
 *       rapid switching between protected apps re-challenges each one.
 *  AI-5 seeded stress (2000 steps): after any disconnect, and for any
 *       package not authorized since, a protected observation is CHALLENGE.
 */
class P18M3AccessibilityInvariantsTest {
    private val a = "com.example.bank"
    private val b = "com.example.mail"
    private val launcher = "com.example.launcher"

    private fun disconnect() {
        // AccessibilityLockService.onUnbind / onDestroy with protection on.
        if (WatcherTeardownPolicy.revokesOnAccessibilityDisconnect(protectionEnabled = true)) {
            ProtectionAccessState.revokeAll()
        }
    }

    @Before
    fun reset() {
        ProtectionAccessState.revokeAll()
        ProtectionRuntime.invalidateChallengeHandoff()
        ProtectionAccessState.setGracePeriod(0L)
        ProtectionAccessState.observeForeground(launcher, protected = false, nowElapsedMs = 0L)
    }

    @Test
    fun ai1ExpiredGrantIsNeverRevivedByReconnection() {
        ProtectionAccessState.authorize(a, 60_000L, 1_000L)
        assertEquals(ALLOW, ProtectionAccessState.observeForeground(a, true, 1_001L))
        // Outage with no disconnect callback observed (OEM kill of the
        // binding only); the window expires while nothing is reported.
        val afterExpiry = 1_001L + 60_000L + 1L // the ALLOW above slid the window
        assertEquals(CHALLENGE, ProtectionAccessState.observeForeground(a, true, afterExpiry))
        // Even a renewing report right after does not bring it back.
        assertEquals(CHALLENGE,
            ProtectionAccessState.observeForeground(a, true, afterExpiry + 1, mayRenew = true))
        assertFalse(ProtectionAccessState.isAuthorized(a))
    }

    @Test
    fun ai2ProtectedSetChangeDuringOutageNeverRevivesTheGrant() {
        for (withRevocation in listOf(true, false)) {
            reset()
            ProtectionAccessState.authorize(a, 600_000L, 1_000L)
            if (withRevocation) disconnect()
            ProtectionAccessState.retainProtectedPackages(setOf(b))      // a unprotected
            ProtectionAccessState.retainProtectedPackages(setOf(a, b))   // a protected again
            assertEquals("revocation=$withRevocation", CHALLENGE,
                ProtectionAccessState.observeForeground(a, true, 2_000L))
        }
    }

    @Test
    fun ai3GraceAbsenceSpanningADisconnectChallenges() {
        ProtectionAccessState.setGracePeriod(60_000L)
        ProtectionAccessState.authorize(a, 600_000L, 1_000L)
        assertEquals(ALLOW, ProtectionAccessState.observeForeground(a, true, 1_001L))
        ProtectionAccessState.observeForeground(launcher, false, 2_000L) // away, grace starts
        disconnect()
        assertEquals(CHALLENGE, ProtectionAccessState.observeForeground(a, true, 3_000L))
    }

    @Test
    fun ai4NoCrossAppAllowAndRapidSwitchingReChallenges() {
        ProtectionAccessState.authorize(a, 600_000L, 1_000L)
        assertEquals(CHALLENGE, ProtectionAccessState.observeForeground(b, true, 1_001L))
        var now = 2_000L
        repeat(100) {
            ProtectionAccessState.authorize(a, 600_000L, ++now)
            assertEquals(ALLOW, ProtectionAccessState.observeForeground(a, true, ++now))
            assertEquals("switch $it to b", CHALLENGE,
                ProtectionAccessState.observeForeground(b, true, ++now))
            ProtectionAccessState.authorize(b, 600_000L, ++now)
            assertEquals(ALLOW, ProtectionAccessState.observeForeground(b, true, ++now))
            assertEquals("switch $it back to a", CHALLENGE,
                ProtectionAccessState.observeForeground(a, true, ++now))
        }
    }

    @Test
    fun ai5SeededStressNoGrantSurvivesADisconnect() {
        val rnd = Random(1803)
        val packages = listOf(a, b, "com.example.photos")
        val authorizedSinceRevoke = mutableSetOf<String>()
        var now = 10_000L
        repeat(2_000) { step ->
            now += rnd.nextLong(1L, 5_000L)
            when (rnd.nextInt(5)) {
                0 -> {
                    val p = packages[rnd.nextInt(packages.size)]
                    ProtectionAccessState.authorize(p, 600_000L, now)
                    authorizedSinceRevoke += p
                }
                1 -> {
                    disconnect()
                    authorizedSinceRevoke.clear()
                }
                2 -> ProtectionAccessState.setGracePeriod(if (rnd.nextBoolean()) 0L else 30_000L)
                3 -> ProtectionAccessState.observeForeground(launcher, false, now)
                else -> {
                    val p = packages[rnd.nextInt(packages.size)]
                    val d = ProtectionAccessState.observeForeground(p, true, now)
                    if (p !in authorizedSinceRevoke) {
                        assertEquals("step $step $p", CHALLENGE, d)
                    }
                    if (d == CHALLENGE) authorizedSinceRevoke -= p
                }
            }
        }
    }
}
