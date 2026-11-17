package com.smartapplock.app

import com.smartapplock.app.NotificationPrivacyEngine.Posted
import com.smartapplock.app.NotificationPrivacyEngine.RemovalCause
import com.smartapplock.app.NotificationPrivacyPolicy.Mode
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Phase 14 / M2: privacy modes engine (JVM, deterministic fake port).
 * Simulated: nothing here runs Android's notification system, so none of it
 * is evidence of device behaviour (heads-up timing, OEM shades, wearables).
 */
class NotificationPrivacyEngineTest {
    private val own = "com.smartapplock.app"
    private val bank = "com.bank.app"
    private val chat = "org.chat.app"
    private val open = "com.news.app" // not protected
    private val salt = ByteArray(16) { it.toByte() }

    private class FakePort(var state: NotificationPrivacyPolicy.State, val salt: ByteArray) : NotificationPrivacyEngine.Port {
        val cancelled = mutableListOf<String>()
        val posted = mutableListOf<NotificationPrivacyEngine.Placeholder>()
        var canPost = true
        var cancelWorks = true
        val labels = mutableMapOf("com.bank.app" to "Bank", "org.chat.app" to "Chat")

        override fun state() = state
        override fun placeholderTag(packageName: String) = NotificationPrivacyEngine.placeholderTag(salt, packageName)
        override fun appLabel(packageName: String) = labels[packageName]
        override fun canPostPlaceholders(mode: Mode) = canPost
        override fun cancelSource(key: String): Boolean {
            if (!cancelWorks) return false
            cancelled += key
            return true
        }
        override fun postPlaceholder(placeholder: NotificationPrivacyEngine.Placeholder): Boolean {
            posted += placeholder
            return true
        }
    }

    private lateinit var port: FakePort
    private lateinit var engine: NotificationPrivacyEngine

    private fun state(
        modes: Map<String, Mode> = mapOf(bank to Mode.HIDE_CONTENT, chat to Mode.MAXIMUM, open to Mode.MAXIMUM),
        protectedSet: Set<String> = setOf(bank, chat),
        enabled: Boolean = true,
        invalid: Boolean = false,
    ) = NotificationPrivacyPolicy.State(own, enabled, protectedSet, modes, invalid)

    private fun n(pkg: String, key: String = "0|$pkg|1|null|10123", flags: Int = 0, sameUser: Boolean = true, tag: String? = null) =
        Posted(key, pkg, flags, sameUser, tag)

    private fun tag(pkg: String) = NotificationPrivacyEngine.placeholderTag(salt, pkg)

    /** Android confirms the listener's cancellation. */
    private fun confirm(p: Posted) = engine.onRemoved(p, RemovalCause.LISTENER)

    @Before
    fun setUp() {
        port = FakePort(state(), salt)
        engine = NotificationPrivacyEngine(port)
        engine.onConnected(emptyList())
    }

    @Test
    fun ownNotificationsAreNeverProcessedNoRecursion() {
        // The protection service notification and our placeholders (any tag).
        for (p in listOf(n(own, "fgs"), n(own, "ph", tag = tag(bank)), n(own, "x", tag = "other"))) {
            engine.onPosted(p)
            engine.onRemoved(p, RemovalCause.LISTENER)
        }
        assertTrue(port.cancelled.isEmpty())
        assertTrue(port.posted.isEmpty())
        // Even if the store were invalid (strictest), our own app is ignored.
        port.state = state(invalid = true, protectedSet = setOf(bank, own))
        engine.onPosted(n(own, "fgs2"))
        assertTrue(port.cancelled.isEmpty())
    }

    @Test
    fun unprotectedOffOtherUserOrProtectionDisabledAreNeverTouched() {
        engine.onPosted(n(open)) // stored MAXIMUM but not protected
        engine.onPosted(n(bank, sameUser = false)) // work profile / other user
        port.state = state(modes = mapOf(chat to Mode.MAXIMUM)) // bank Off
        engine.onPosted(n(bank))
        port.state = state(enabled = false)
        engine.onPosted(n(chat))
        engine.onPosted(n(bank))
        assertTrue(port.cancelled.isEmpty())
        // Unrelated removals never produce placeholders.
        engine.onRemoved(n(open), RemovalCause.LISTENER)
        assertTrue(port.posted.isEmpty())
    }

    @Test
    fun hideContentShowsOnlyAppNameAndNewNotificationAfterConfirmedRemoval() {
        val p = n(bank)
        engine.onPosted(p)
        assertEquals(listOf(p.key), port.cancelled)
        assertTrue("no placeholder before Android confirms the removal", port.posted.isEmpty())
        confirm(p)
        val ph = port.posted.single()
        assertEquals(bank, ph.sourcePackage)
        assertEquals("Bank", ph.title)
        assertEquals("New notification", ph.text)
        assertEquals("New notification", ph.publicTitle)
        assertEquals(NotificationPrivacyEngine.LockScreen.PRIVATE, ph.lockScreen)
        assertEquals(NotificationPrivacyEngine.CHANNEL_HIDDEN, ph.channelId)
        assertEquals(tag(bank), ph.tag)
        // The spec has no field that could carry content, sender, images or actions.
        assertEquals(
            setOf("tag", "sourcePackage", "mode", "channelId", "title", "text", "publicTitle", "lockScreen", "importance"),
            NotificationPrivacyEngine.Placeholder::class.java.declaredFields.map { it.name }.toSet(),
        )
    }

    @Test
    fun maximumShowsNoAppNameIsSilentAndSecretOnTheLockScreen() {
        val p = n(chat)
        engine.onPosted(p)
        confirm(p)
        val ph = port.posted.single()
        assertEquals("New notification", ph.title)
        assertNull(ph.text)
        assertNull(ph.publicTitle)
        assertEquals(NotificationPrivacyEngine.LockScreen.SECRET, ph.lockScreen)
        assertEquals(NotificationPrivacyEngine.Importance.MIN, ph.importance)
        assertEquals(NotificationPrivacyEngine.CHANNEL_MAXIMUM, ph.channelId)
        val visible = listOfNotNull(ph.title, ph.text, ph.publicTitle, ph.tag).joinToString(" ")
        assertFalse(visible.contains("Chat"))
        assertFalse(visible.contains(chat))
        assertFalse(visible.contains("chat"))
    }

    @Test
    fun hideContentWithoutALabelFallsBackToNewNotificationOnly() {
        port.labels.remove(bank)
        val p = n(bank)
        engine.onPosted(p)
        confirm(p)
        val ph = port.posted.single()
        assertEquals("New notification", ph.title)
        assertNull(ph.text)
        assertEquals(
            "x".repeat(60),
            NotificationPrivacyEngine.placeholderFor(bank, Mode.HIDE_CONTENT, "t", "x".repeat(200)).title,
        )
    }

    @Test
    fun repeatedPostsUpdatesAndGroupsGiveExactlyOnePlaceholderPerApp() {
        val summary = n(bank, "k-summary", flags = 0x200) // FLAG_GROUP_SUMMARY: removable
        val child1 = n(bank, "k-1")
        val child2 = n(bank, "k-2")
        for (p in listOf(summary, child1, child2, child1 /* update of the same key */)) {
            engine.onPosted(p)
            confirm(p)
        }
        assertEquals(listOf("k-summary", "k-1", "k-2", "k-1"), port.cancelled)
        assertEquals(1, port.posted.size)
        // Another app gets its own (distinct) placeholder.
        val c = n(chat, "c-1")
        engine.onPosted(c)
        confirm(c)
        assertEquals(2, port.posted.size)
        assertNotEquals(port.posted[0].tag, port.posted[1].tag)
        // A duplicate confirmation (or one for an unknown key) does nothing.
        confirm(c)
        confirm(n(chat, "never-posted"))
        assertEquals(2, port.posted.size)
    }

    @Test
    fun ongoingNoClearAndForegroundServiceNotificationsAreLeftUntouched() {
        for ((i, flags) in listOf(
            NotificationPrivacyEngine.FLAG_ONGOING_EVENT,
            NotificationPrivacyEngine.FLAG_NO_CLEAR,
            NotificationPrivacyEngine.FLAG_FOREGROUND_SERVICE,
            NotificationPrivacyEngine.FLAG_FOREGROUND_SERVICE or NotificationPrivacyEngine.FLAG_NO_CLEAR,
        ).withIndex()) {
            val p = n(chat, "ongoing-$i", flags = flags)
            assertEquals(NotificationPrivacyPolicy.Decision.CANNOT_HIDE, NotificationPrivacyEngine.classify(port.state, p))
            engine.onPosted(p)
        }
        assertTrue(port.cancelled.isEmpty())
        assertTrue(port.posted.isEmpty())
    }

    @Test
    fun anOriginalAndroidDidNotRemoveNeverGetsAPlaceholderBesideIt() {
        val p = n(bank)
        engine.onPosted(p)
        // The app removed it itself (race), or Android refused our cancel.
        engine.onRemoved(p, RemovalCause.OTHER)
        assertTrue(port.posted.isEmpty())
        port.cancelWorks = false
        val q = n(chat, "c-x")
        engine.onPosted(q)
        assertEquals(0, engine.pendingCount)
        confirm(q)
        assertTrue(port.posted.isEmpty())
    }

    @Test
    fun dismissingOrOpeningAPlaceholderAllowsTheNextOne() {
        val a = n(bank, "a")
        engine.onPosted(a)
        confirm(a)
        engine.onRemoved(n(own, "ph", tag = tag(bank)), RemovalCause.OTHER) // user dismissed / tapped it
        assertTrue(engine.shownModes().isEmpty())
        val b = n(bank, "b")
        engine.onPosted(b)
        confirm(b)
        assertEquals(2, port.posted.size)
        // A removal of an own notification with a foreign tag changes nothing.
        engine.onRemoved(n(own, "fgs", tag = null), RemovalCause.OTHER)
        assertEquals(mapOf(bank to Mode.HIDE_CONTENT), engine.shownModes())
    }

    @Test
    fun missingNotificationPermissionRemovesWithoutPlaceholderAndRecovers() {
        port.canPost = false // POST_NOTIFICATIONS revoked / channel blocked
        val a = n(chat, "a")
        engine.onPosted(a)
        confirm(a)
        assertEquals(listOf("a"), port.cancelled)
        assertTrue("never a placeholder without permission", port.posted.isEmpty())
        assertTrue(engine.shownModes().isEmpty())
        port.canPost = true // permission granted again
        val b = n(chat, "b")
        engine.onPosted(b)
        confirm(b)
        assertEquals(1, port.posted.size)
    }

    @Test
    fun reconnectionRebuildsStateWithoutDuplicatesAndSweepsActiveNotifications() {
        val a = n(bank, "a")
        engine.onPosted(a)
        confirm(a)
        // Access revoked (or process death): Android unbinds the listener.
        engine.onDisconnected()
        assertFalse(engine.isConnected)
        assertEquals(0, engine.pendingCount)
        // Callbacks after disconnection are ignored.
        engine.onPosted(n(chat, "late"))
        engine.onRemoved(n(chat, "late"), RemovalCause.LISTENER)
        assertEquals(listOf("a"), port.cancelled)
        port.posted.clear()

        // Reconnect: our bank placeholder is still visible, plus originals
        // posted while we were not bound.
        engine.onConnected(
            listOf(
                n(own, "ph-bank", tag = tag(bank)),
                n(own, "fgs"),
                n(chat, "c-visible"),
                n(chat, "c-ongoing", flags = NotificationPrivacyEngine.FLAG_ONGOING_EVENT),
                n(open, "o-visible"),
            ),
        )
        assertEquals("re-rendered in place (same tag)", listOf(tag(bank)), port.posted.map { it.tag })
        assertEquals(listOf("a", "c-visible"), port.cancelled)
        assertEquals(mapOf(bank to Mode.HIDE_CONTENT), engine.shownModes())
        // The bank placeholder is not posted again for the next bank notification.
        val b = n(bank, "b")
        engine.onPosted(b)
        confirm(b)
        assertEquals(1, port.posted.count { it.sourcePackage == bank })
        confirm(n(chat, "c-visible"))
        assertEquals(1, port.posted.count { it.sourcePackage == chat })
    }

    @Test
    fun configurationChangesOnlyEverMakePlaceholdersStricterAndSweepActive() {
        val a = n(bank, "a")
        engine.onPosted(a)
        confirm(a)
        // Bank: Hide content -> Maximum. Its placeholder loses the app name.
        port.state = state(modes = mapOf(bank to Mode.MAXIMUM, chat to Mode.MAXIMUM))
        engine.onConfigurationChanged(emptyList())
        assertEquals(2, port.posted.size)
        assertEquals("New notification", port.posted.last().title)
        assertEquals(tag(bank), port.posted.last().tag)
        // Maximum -> Hide content: the visible placeholder is NOT weakened in place.
        port.state = state()
        engine.onConfigurationChanged(emptyList())
        assertEquals(2, port.posted.size)
        // ...nor when the next bank notification arrives: it stays nameless
        // until the user opens or dismisses it.
        val b = n(bank, "b")
        engine.onPosted(b)
        confirm(b)
        assertEquals(2, port.posted.size)
        assertEquals(mapOf(bank to Mode.MAXIMUM), engine.shownModes())
        // Newly protected app with privacy on: its visible originals are swept.
        port.state = state(protectedSet = setOf(bank, chat, open))
        engine.onConfigurationChanged(listOf(n(open, "o-1"), n(open, "o-2", flags = NotificationPrivacyEngine.FLAG_FOREGROUND_SERVICE)))
        assertEquals(listOf("a", "b", "o-1"), port.cancelled)
    }

    @Test
    fun aModeTurnedOffBeforeConfirmationPostsNothing() {
        val a = n(bank, "a")
        engine.onPosted(a)
        port.state = state(modes = mapOf(chat to Mode.MAXIMUM))
        confirm(a)
        assertTrue(port.posted.isEmpty())
    }

    @Test
    fun anUnreadableNativeStoreTreatsProtectedAppsAsMaximumWithoutNames() {
        port.state = state(modes = emptyMap(), invalid = true)
        val a = n(bank, "a")
        engine.onPosted(a)
        confirm(a)
        assertEquals("New notification", port.posted.single().title)
        assertEquals(Mode.MAXIMUM, port.posted.single().mode)
        engine.onPosted(n(open, "o")) // still never an unprotected app
        assertEquals(listOf("a"), port.cancelled)
    }

    @Test
    fun pendingRemovalsAreBounded() {
        repeat(NotificationPrivacyEngine.MAX_PENDING + 25) { engine.onPosted(n(bank, "k$it")) }
        assertEquals(NotificationPrivacyEngine.MAX_PENDING, engine.pendingCount)
        confirm(n(bank, "k0")) // evicted (oldest): no placeholder
        assertTrue(port.posted.isEmpty())
        confirm(n(bank, "k${NotificationPrivacyEngine.MAX_PENDING + 24}"))
        assertEquals(1, port.posted.size)
    }

    @Test
    fun placeholderTagsAreOpaqueSaltedAndDistinct() {
        val t = NotificationPrivacyEngine.placeholderTag(salt, bank)
        assertEquals(t, NotificationPrivacyEngine.placeholderTag(salt, bank))
        assertTrue(t.startsWith(NotificationPrivacyEngine.TAG_PREFIX))
        assertEquals(NotificationPrivacyEngine.TAG_PREFIX.length + 32, t.length)
        for (part in listOf("bank", "com", bank)) assertFalse(t.contains(part))
        assertNotEquals(t, NotificationPrivacyEngine.placeholderTag(salt, chat))
        assertNotEquals(t, NotificationPrivacyEngine.placeholderTag(ByteArray(16), bank))
    }

    @Test
    fun removalCauseMapping() {
        assertEquals(RemovalCause.UNKNOWN, NotificationPrivacyEngine.removalCause(25, 10))
        assertEquals(RemovalCause.UNKNOWN, NotificationPrivacyEngine.removalCause(30, null))
        assertEquals(RemovalCause.LISTENER, NotificationPrivacyEngine.removalCause(26, 10))
        assertEquals(RemovalCause.LISTENER, NotificationPrivacyEngine.removalCause(34, 11))
        for (reason in listOf(1, 2, 3, 8, 9, 12)) {
            assertEquals(RemovalCause.OTHER, NotificationPrivacyEngine.removalCause(34, reason))
        }
        // Android 7.x has no reason: the removal of a pending key confirms it.
        val a = n(bank, "a")
        engine.onPosted(a)
        engine.onRemoved(a, RemovalCause.UNKNOWN)
        assertEquals(1, port.posted.size)
    }

    @Test
    fun placeholderTapOnlyOpensTheProtectedAppWhichTheExistingLockChallenges() {
        assertTrue(NotificationPrivacyEngine.tapTargetAllowed(own, bank, bank))
        assertFalse(NotificationPrivacyEngine.tapTargetAllowed(own, bank, own))
        assertFalse(NotificationPrivacyEngine.tapTargetAllowed(own, bank, chat))
        assertFalse(NotificationPrivacyEngine.tapTargetAllowed(own, bank, null))
        assertFalse(NotificationPrivacyEngine.tapTargetAllowed(own, own, own))
        // Replay of the resulting foreground reports (shade -> protected app),
        // through the same policy WatcherService uses: a challenge, never ALLOW.
        ProtectionAccessState.revokeAll()
        ProtectionAccessState.setGracePeriod(0L)
        val t0 = 5_000_000L
        ProtectionAccessState.observeForeground("com.example.launcher", false, t0)
        ProtectionAccessState.observeForeground("com.android.systemui", false, t0 + 1)
        assertEquals(
            ProtectionAccessState.Decision.CHALLENGE,
            ProtectionAccessState.observeForeground(bank, true, t0 + 2),
        )
        assertFalse(ProtectionAccessState.isAuthorized(bank))
        ProtectionAccessState.revokeAll()
    }

    @Test
    fun listenerReadsOnlyNotificationMetadata() {
        val src = locate("android/app/src/main/kotlin/com/smartapplock/app/SalNotificationListenerService.kt").readText()
        val code = src.lines().map { it.trim() }
            .filterNot { it.startsWith("*") || it.startsWith("//") || it.startsWith("/*") || it.startsWith("import ") }
            .joinToString("\n")
        // The only member of the original Notification that is read: flags.
        val reads = Regex("""\.notification\??\.(\w+)""").findAll(code).map { it.groupValues[1] }.toSet()
        assertEquals(setOf("flags"), reads)
        for (forbidden in listOf("extras", "EXTRA_", "tickerText", "contentIntent", "actions", "getText", "Log.", "DiagLog", "println")) {
            assertFalse("listener must not use $forbidden", code.contains(forbidden))
        }
        // Other apps' tags are never handed to the engine.
        assertTrue(code.contains("tag = if (own) sbn.tag else null"))
        val poster = locate("android/app/src/main/kotlin/com/smartapplock/app/NotificationPlaceholders.kt").readText()
        for (forbidden in listOf("StatusBarNotification", "extras", "Log.", "DiagLog", "addAction", "setLargeIcon")) {
            assertFalse("placeholder poster must not use $forbidden", poster.contains(forbidden))
        }
    }

    private fun locate(rel: String): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val f = File(dir, rel)
            if (f.isFile) return f
            dir = dir.parentFile
        }
        throw AssertionError("not found: $rel")
    }
}
