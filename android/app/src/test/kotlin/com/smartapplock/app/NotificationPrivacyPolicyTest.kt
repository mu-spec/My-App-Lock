package com.smartapplock.app

import com.smartapplock.app.NotificationPrivacyPolicy.Decision
import com.smartapplock.app.NotificationPrivacyPolicy.Mode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Phase 14 / M1: notification privacy policy (pure). */
class NotificationPrivacyPolicyTest {
    private val own = "com.smartapplock.app"
    private val bank = "com.bank.app"
    private val chat = "org.chat.app"
    private val other = "com.other.app"

    private fun state(
        modes: Map<String, Mode> = mapOf(bank to Mode.HIDE_CONTENT, chat to Mode.MAXIMUM),
        protected: Set<String> = setOf(bank, chat, other),
        enabled: Boolean = true,
        invalid: Boolean = false,
    ) = NotificationPrivacyPolicy.State(own, enabled, protected, modes, invalid)

    @Test
    fun modeIdsAreStableAndRanked() {
        assertEquals(listOf("off", "hide_content", "maximum"), Mode.values().map { it.id })
        assertEquals(listOf(0, 1, 2), Mode.values().map { it.rank })
        assertNull(Mode.fromId("MAXIMUM"))
        assertNull(Mode.fromId(null))
    }

    @Test
    fun decideCoversEveryBranch() {
        val s = state()
        assertEquals(Decision.IGNORE_OWN_APP, NotificationPrivacyPolicy.decide(s, own, false, true))
        assertEquals(Decision.IGNORE_NOT_PROTECTED, NotificationPrivacyPolicy.decide(s, "com.x.y", false, true))
        assertEquals(Decision.IGNORE_PRIVACY_OFF, NotificationPrivacyPolicy.decide(s, other, false, true))
        assertEquals(Decision.HIDE_CONTENT, NotificationPrivacyPolicy.decide(s, bank, false, true))
        assertEquals(Decision.MAXIMUM, NotificationPrivacyPolicy.decide(s, chat, false, true))
        assertEquals(Decision.CANNOT_HIDE, NotificationPrivacyPolicy.decide(s, bank, true, true))
        assertEquals(Decision.CANNOT_HIDE, NotificationPrivacyPolicy.decide(s, chat, false, false))
    }

    @Test
    fun unprotectedOrDisabledProtectionIgnoresStoredModes() {
        val unprotected = state(protected = setOf(other))
        assertEquals(Decision.IGNORE_NOT_PROTECTED, NotificationPrivacyPolicy.decide(unprotected, bank, false, true))
        assertEquals(Mode.OFF, NotificationPrivacyPolicy.effectiveMode(unprotected, chat))
        val disabled = state(enabled = false)
        assertEquals(Decision.IGNORE_NOT_PROTECTED, NotificationPrivacyPolicy.decide(disabled, chat, false, true))
        assertFalse(NotificationPrivacyPolicy.listenerWanted(disabled))
    }

    @Test
    fun invalidStoreIsStrictestForProtectedAppsNeverOff() {
        val s = state(modes = emptyMap(), invalid = true)
        assertEquals(Mode.MAXIMUM, NotificationPrivacyPolicy.effectiveMode(s, other))
        assertEquals(Decision.MAXIMUM, NotificationPrivacyPolicy.decide(s, other, false, true))
        assertEquals(Decision.IGNORE_NOT_PROTECTED, NotificationPrivacyPolicy.decide(s, "com.x.y", false, true))
        assertEquals(Decision.IGNORE_OWN_APP, NotificationPrivacyPolicy.decide(s, own, false, true))
        assertTrue(NotificationPrivacyPolicy.listenerWanted(s))
    }

    @Test
    fun listenerWantedOnlyWhileAProtectedAppHasPrivacy() {
        assertTrue(NotificationPrivacyPolicy.listenerWanted(state()))
        assertFalse(NotificationPrivacyPolicy.listenerWanted(state(modes = emptyMap())))
        assertFalse(NotificationPrivacyPolicy.listenerWanted(state(protected = setOf(other))))
    }

    @Test
    fun normalizeRefusesTheWholeSnapshotOnAnyInvalidEntry() {
        assertEquals(
            mapOf(bank to Mode.HIDE_CONTENT),
            NotificationPrivacyPolicy.normalize(mapOf(bank to "hide_content", other to "off")),
        )
        assertNull(NotificationPrivacyPolicy.normalize(mapOf(bank to "hide_content", "bad pkg" to "maximum")))
        assertNull(NotificationPrivacyPolicy.normalize(mapOf(bank to "secret")))
        assertNull(NotificationPrivacyPolicy.normalize(mapOf(bank to 1)))
        assertNull(NotificationPrivacyPolicy.normalize(mapOf(7 to "maximum")))
        assertNull(NotificationPrivacyPolicy.normalize(null))
        val tooMany = (0..NotificationPrivacyPolicy.MAX_ENTRIES).associate { "com.a.p$it" to "maximum" }
        assertNull(NotificationPrivacyPolicy.normalize(tooMany))
        assertEquals(emptyMap<String, Mode>(), NotificationPrivacyPolicy.normalize(emptyMap<String, String>()))
    }

    @Test
    fun codecRoundTripsAndRejectsDamage() {
        val modes = mapOf(bank to Mode.HIDE_CONTENT, chat to Mode.MAXIMUM)
        val enc = NotificationPrivacyPolicy.encode(modes + (other to Mode.OFF))
        assertEquals(setOf("$bank|hide_content", "$chat|maximum"), enc)
        assertEquals(modes, NotificationPrivacyPolicy.decode(enc))
        assertEquals(emptyMap<String, Mode>(), NotificationPrivacyPolicy.decode(emptySet()))
        for (bad in listOf("$bank|off", "$bank|", "|maximum", "$bank", "$bank|maximum|x", "bad|maximum")) {
            assertNull(bad, NotificationPrivacyPolicy.decode(setOf(bad)))
        }
        assertNull(NotificationPrivacyPolicy.decode(setOf("$bank|maximum", "$bank|hide_content")))
        assertNull(NotificationPrivacyPolicy.decode(null))
    }

    @Test
    fun settingsLinksAreAllowlisted() {
        assertEquals(
            listOf(NotificationPrivacyPolicy.ACTION_LISTENER_SETTINGS),
            NotificationPrivacyPolicy.accessSettingsActions(29),
        )
        assertEquals(
            listOf(
                NotificationPrivacyPolicy.ACTION_LISTENER_DETAIL_SETTINGS,
                NotificationPrivacyPolicy.ACTION_LISTENER_SETTINGS,
            ),
            NotificationPrivacyPolicy.accessSettingsActions(30),
        )
        assertEquals("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS", NotificationPrivacyPolicy.ACTION_LISTENER_SETTINGS)
        assertTrue(NotificationPrivacyPolicy.mayOpenAppNotificationSettings(bank, setOf(bank)))
        assertFalse(NotificationPrivacyPolicy.mayOpenAppNotificationSettings(other, setOf(bank)))
        assertFalse(NotificationPrivacyPolicy.mayOpenAppNotificationSettings(null, setOf(bank)))
        assertFalse(NotificationPrivacyPolicy.mayOpenAppNotificationSettings("x", setOf("x")))
    }

    @Test
    fun legacyAccessListParsing() {
        val cls = "com.smartapplock.app.SalNotificationListenerService"
        assertTrue(NotificationPrivacyPolicy.listenerEnabledIn("a.b/.L:$own/$cls", own, cls))
        assertTrue(NotificationPrivacyPolicy.listenerEnabledIn("$own/.SalNotificationListenerService", own, cls))
        assertFalse(NotificationPrivacyPolicy.listenerEnabledIn("com.smartapplock.app.debug/$cls", own, cls))
        assertFalse(NotificationPrivacyPolicy.listenerEnabledIn("", own, cls))
        assertFalse(NotificationPrivacyPolicy.listenerEnabledIn(null, own, cls))
    }
}
