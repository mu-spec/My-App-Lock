package com.smartapplock.app

import android.content.Context
import android.content.SharedPreferences
import com.smartapplock.app.ProtectionAccessState.Decision
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * Phase 18 / M3 F18-M3-1: stale Accessibility authority after an OBSERVED
 * disconnect. SIMULATED (evidence B, JVM) plus source wiring (evidence C).
 *
 * Defect (baseline ec5dbf1): WatcherService ignored every UsageEvents report
 * for 5 s after the last Accessibility event, and nothing cleared that
 * timestamp when Accessibility disconnected. A protected app opened in that
 * window was not shielded until the window ran out (up to about 5 s plus one
 * 1 s poll), even though the source that "had authority" was gone.
 *
 * The [Pipeline] replays the order of `WatcherService.reportForeground` for
 * the parts that matter here (authority gate -> isProtected ->
 * observeForeground -> ensurePendingChallenge) against the PRODUCTION
 * [AccessibilityConnection], [AccessibilityAuthority], [ProtectionAccessState],
 * [WatcherTeardownPolicy] and [ProtectionStateStore] (in-memory preferences).
 * AA-9 pins that order and the wiring in the real sources.
 *
 * Silent OEM kills (no onUnbind/onDestroy) are NOT observable and are not
 * claimed to be fixed here; see the M3 report (R2).
 */
class P18M3AccessibilityAuthorityTest {
    private val launcher = "com.example.launcher"
    private val bank = "com.example.bank"
    private val mail = "com.example.mail"

    private lateinit var ctx: FakeContext
    private lateinit var pipe: Pipeline

    @Before
    fun setUp() {
        AccessibilityConnection.onChange = null
        AccessibilityConnection.onDisconnected()
        AccessibilityConnection.authority.invalidate()
        ProtectionAccessState.revokeAll()
        ProtectionRuntime.invalidateChallengeHandoff()
        ProtectionAccessState.setGracePeriod(0L)
        ProtectionAccessState.observeForeground(launcher, protected = false, nowElapsedMs = 0L)
        ctx = FakeContext()
        ctx.prefs.data["enabled"] = true
        ctx.prefs.data["protected_packages"] = setOf(bank, mail)
        pipe = Pipeline(ctx)
    }

    @After
    fun tearDown() {
        AccessibilityConnection.onDisconnected()
        AccessibilityConnection.authority.invalidate()
        ProtectionAccessState.revokeAll()
    }

    // -- AA-1 reproduction: an observed disconnect ends the authority -----------

    @Test
    fun aa1ObservedDisconnectInvalidatesStaleAuthorityImmediately() {
        AccessibilityConnection.onConnected()
        pipe.report(launcher, Src.ACCESSIBILITY, 10_000L)
        assertTrue(AccessibilityConnection.authority.defersUsageEvents(10_001L))
        AccessibilityConnection.onDisconnected()
        assertFalse("disconnect must end Accessibility authority at once",
            AccessibilityConnection.authority.defersUsageEvents(10_001L))
    }

    // -- AA-2 the fallback is no longer delayed by the old timestamp -----------

    @Test
    fun aa2UsageEventsFallbackShieldsOnTheFirstPollAfterDisconnect() {
        AccessibilityConnection.onConnected()
        pipe.report(launcher, Src.ACCESSIBILITY, 10_000L)
        pipe.disconnect()
        // The first 1 s poll inside the old 5 s window now enforces.
        val out = pipe.report(bank, Src.USAGE_EVENTS, 11_000L)
        assertEquals(Outcome.CHALLENGE, out)
        assertEquals(bank, ProtectionStateStore.pendingChallenge(ctx)?.packageName)
    }

    // -- AA-3 no stale grant survives ----------------------------------------

    @Test
    fun aa3NoStaleGrantSurvivesTheDisconnect() {
        AccessibilityConnection.onConnected()
        ProtectionAccessState.authorize(bank, 600_000L, 10_000L)
        assertEquals(Outcome.ALLOW, pipe.report(bank, Src.ACCESSIBILITY, 10_001L))
        pipe.disconnect()
        assertFalse(ProtectionAccessState.isAuthorized(bank))
        assertEquals(Outcome.CHALLENGE, pipe.report(bank, Src.USAGE_EVENTS, 10_500L))
        assertFalse(ProtectionAccessState.isAuthorized(bank))
    }

    // -- AA-4 no duplicate challenges ----------------------------------------

    @Test
    fun aa4RepeatedPollsReuseOneTicket() {
        AccessibilityConnection.onConnected()
        pipe.report(launcher, Src.ACCESSIBILITY, 10_000L)
        pipe.disconnect()
        assertNull("no ticket before the protected report", pipe.lastTicket)
        assertEquals(Outcome.CHALLENGE, pipe.report(bank, Src.USAGE_EVENTS, 11_000L))
        val first = requireNotNull(pipe.lastTicket)
        repeat(20) { i ->
            assertEquals(Outcome.CHALLENGE,
                pipe.report(bank, Src.USAGE_EVENTS, 12_000L + i * 1_000L))
            assertEquals("poll $i must not mint a new ticket", first, pipe.lastTicket)
        }
        assertEquals(first, ProtectionStateStore.pendingChallenge(ctx))
        assertEquals(first.generation, ctx.prefs.data["next_challenge_generation"])
    }

    // -- AA-5 reconnection ----------------------------------------------------

    @Test
    fun aa5ReconnectionRestoresAuthorityOnlyWithAFreshEventAndNeverRevivesGrants() {
        AccessibilityConnection.onConnected()
        ProtectionAccessState.authorize(bank, 600_000L, 10_000L)
        pipe.report(bank, Src.ACCESSIBILITY, 10_001L)
        pipe.disconnect()
        AccessibilityConnection.onConnected()
        // Bound again, but no event yet: nothing fresh to defer to.
        assertFalse(AccessibilityConnection.authority.defersUsageEvents(10_500L))
        // First fresh event: the old grant is gone, so it challenges.
        assertEquals(Outcome.CHALLENGE, pipe.report(bank, Src.ACCESSIBILITY, 11_000L))
        // The fresh event has authority again for the unchanged 5 s window.
        assertEquals(Outcome.DEFERRED, pipe.report(launcher, Src.USAGE_EVENTS, 15_999L))
        assertEquals(Outcome.ALLOW, pipe.report(launcher, Src.USAGE_EVENTS, 16_000L))
        assertEquals(5_000L, AccessibilityAuthority.WINDOW_MS)
    }

    // -- AA-6 missing UsageEvents never authorizes ----------------------------

    @Test
    fun aa6MissingUsageEventsNeverAuthorizes() {
        AccessibilityConnection.onConnected()
        ProtectionAccessState.authorize(bank, 600_000L, 10_000L)
        pipe.report(bank, Src.ACCESSIBILITY, 10_001L)
        pipe.disconnect()
        // getForegroundPackage() == null (no usage access / no events): the
        // poll reports nothing. Time passes; nothing is granted.
        repeat(30) { pipe.poll(null, 11_000L + it * 1_000L) }
        assertFalse(ProtectionAccessState.isAuthorized(bank))
        assertFalse(ProtectionAccessState.isAuthorized(mail))
        assertEquals(Outcome.CHALLENGE, pipe.report(mail, Src.USAGE_EVENTS, 60_000L))
        assertEquals(Outcome.CHALLENGE, pipe.report(bank, Src.ACCESSIBILITY, 60_100L))
    }

    // -- AA-7 the disconnect needs no running watcher -------------------------

    @Test
    fun aa7InvalidationDoesNotDependOnARunningWatcher() {
        AccessibilityConnection.onChange = null // WatcherService not running
        AccessibilityConnection.onConnected()
        AccessibilityConnection.authority.onAccessibilityReport(10_000L)
        AccessibilityConnection.onDisconnected()
        assertFalse(AccessibilityConnection.authority.defersUsageEvents(10_001L))
        // And with a watcher callback installed, it runs after invalidation.
        var deferredSeenByCallback: Boolean? = null
        AccessibilityConnection.authority.onAccessibilityReport(20_000L)
        AccessibilityConnection.onChange = {
            deferredSeenByCallback = AccessibilityConnection.authority.defersUsageEvents(20_001L)
        }
        AccessibilityConnection.onDisconnected()
        AccessibilityConnection.onChange = null
        assertEquals(false, deferredSeenByCallback)
    }

    // -- AA-8 a bound source keeps its authority (no D1 / U1 change) ----------

    @Test
    fun aa8WithoutADisconnectTheAuthorityWindowIsUnchanged() {
        AccessibilityConnection.onConnected()
        pipe.report(launcher, Src.ACCESSIBILITY, 10_000L)
        assertEquals(Outcome.DEFERRED, pipe.report(bank, Src.USAGE_EVENTS, 14_999L))
        assertEquals(Outcome.CHALLENGE, pipe.report(bank, Src.USAGE_EVENTS, 15_000L))
        val fresh = AccessibilityAuthority()
        assertFalse(fresh.defersUsageEvents(1L))
        fresh.onAccessibilityReport(100L)
        assertTrue(fresh.defersUsageEvents(5_099L))
        assertFalse(fresh.defersUsageEvents(5_100L))
    }

    // -- AA-9 wiring in the real sources (evidence C) -------------------------

    @Test
    fun aa9WiringDisconnectToWatcherGate() {
        val signals = source("ProtectionHealthSignals.kt")
        val disc = body(signals, "fun onDisconnected()")
        val inv = disc.indexOf("authority.invalidate()")
        assertTrue("onDisconnected must invalidate the authority", inv >= 0)
        assertTrue("invalidate before notifying", inv < disc.indexOf("onChange?.invoke()"))
        assertFalse(body(signals, "fun onConnected()").contains("onAccessibilityReport"))

        val a11y = source("AccessibilityLockService.kt")
        for (cb in listOf("override fun onUnbind(", "override fun onDestroy()")) {
            val b = body(a11y, cb)
            assertTrue(b.contains("AccessibilityConnection.onDisconnected()"))
            assertTrue(b.indexOf("AccessibilityConnection.onDisconnected()") < b.indexOf("revokeOnDisconnect()"))
        }

        val watcher = source("WatcherService.kt")
        assertFalse(watcher.contains("lastAccessibilityElapsedMs"))
        assertFalse(watcher.contains("ACCESSIBILITY_AUTHORITY_MS"))
        assertTrue(watcher.contains("private const val POLL_INTERVAL_MS = 1_000L")) // D1
        val report = body(watcher, "fun reportForeground(")
        val gate = report.indexOf("AccessibilityConnection.authority.defersUsageEvents(now)")
        val mark = report.indexOf("AccessibilityConnection.authority.onAccessibilityReport(now)")
        assertTrue(mark in 0 until gate)
        val protectedAt = report.indexOf("ProtectionStateStore.isProtected(context, packageName)")
        assertTrue("gate before enforcement", gate in 0 until protectedAt)
        assertTrue(protectedAt < report.indexOf("ProtectionAccessState.observeForeground("))
        assertEquals(2, Regex("AccessibilityConnection\\.authority\\.").findAll(watcher).count())
    }

    // -- harness ----------------------------------------------------------------

    private enum class Outcome { DEFERRED, ALLOW, CHALLENGE }

    /** Mirrors WatcherService's ForegroundSource (not JVM-compilable here). */
    private enum class Src { ACCESSIBILITY, USAGE_EVENTS }

    private inner class Pipeline(val ctx: FakeContext) {
        var lastTicket: ProtectionStateStore.PendingChallenge? = null

        fun report(pkg: String, source: Src, now: Long): Outcome {
            if (source == Src.ACCESSIBILITY) {
                AccessibilityConnection.authority.onAccessibilityReport(now)
            } else if (AccessibilityConnection.authority.defersUsageEvents(now)) {
                return Outcome.DEFERRED
            }
            val protected = ProtectionStateStore.isProtected(ctx, pkg)
            val d = ProtectionAccessState.observeForeground(
                pkg, protected, now, mayRenew = source == Src.ACCESSIBILITY,
            )
            if (!protected || d == Decision.ALLOW) return Outcome.ALLOW
            lastTicket = ProtectionStateStore.ensurePendingChallenge(ctx, pkg)
            return Outcome.CHALLENGE
        }

        fun poll(foreground: String?, now: Long) {
            foreground?.let { report(it, Src.USAGE_EVENTS, now) }
        }

        /** AccessibilityLockService.onUnbind / onDestroy, in source order. */
        fun disconnect() {
            AccessibilityConnection.onDisconnected()
            if (WatcherTeardownPolicy.revokesOnAccessibilityDisconnect(
                    ProtectionStateStore.isEnabled(ctx),
                )
            ) {
                ProtectionAccessState.revokeAll()
            }
        }
    }

    private fun body(src: String, signature: String): String {
        val start = src.indexOf(signature)
        assertTrue("missing $signature", start >= 0)
        var depth = 0
        var i = src.indexOf('{', start)
        val open = i
        while (i < src.length) {
            when (src[i]) {
                '{' -> depth++
                '}' -> if (--depth == 0) return src.substring(open, i + 1)
            }
            i++
        }
        error("unbalanced $signature")
    }

    private fun source(name: String): String {
        val relative = "src/main/kotlin/com/smartapplock/app"
        val dir = listOf(File(relative), File("android/app/$relative")).firstOrNull { it.isDirectory }
        assertNotNull("source dir not found from ${File(".").absolutePath}", dir)
        return File(dir, name).readText()
    }

    private class FakePrefs : SharedPreferences {
        val data = mutableMapOf<String, Any>()
        override fun getBoolean(key: String?, defValue: Boolean) = data[key] as? Boolean ?: defValue
        override fun getLong(key: String?, defValue: Long) = data[key] as? Long ?: defValue
        override fun getInt(key: String?, defValue: Int) = data[key] as? Int ?: defValue
        override fun getString(key: String?, defValue: String?) = data[key] as? String ?: defValue
        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String?, defValues: Set<String>?): Set<String>? =
            (data[key] as? Set<String>)?.toSet() ?: defValues
        override fun contains(key: String?) = data.containsKey(key)
        override fun edit(): SharedPreferences.Editor = FakeEditor(this)
    }

    private class FakeEditor(private val prefs: FakePrefs) : SharedPreferences.Editor {
        private val puts = mutableMapOf<String, Any>()
        private val removes = mutableSetOf<String>()
        private fun put(key: String?, value: Any): SharedPreferences.Editor {
            puts[key!!] = value
            return this
        }
        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = put(key, value)
        override fun putLong(key: String?, value: Long): SharedPreferences.Editor = put(key, value)
        override fun putInt(key: String?, value: Int): SharedPreferences.Editor = put(key, value)
        override fun putString(key: String?, value: String?): SharedPreferences.Editor = put(key, value!!)
        override fun putStringSet(key: String?, values: Set<String>?): SharedPreferences.Editor =
            put(key, values!!.toSet())
        override fun remove(key: String?): SharedPreferences.Editor {
            removes += key!!
            return this
        }
        override fun clear(): SharedPreferences.Editor {
            prefs.data.clear()
            return this
        }
        override fun apply() {
            commit()
        }
        override fun commit(): Boolean {
            removes.forEach { prefs.data.remove(it) }
            prefs.data.putAll(puts)
            return true
        }
    }

    private class FakeContext(val prefs: FakePrefs = FakePrefs()) : Context() {
        override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences = prefs
    }
}
