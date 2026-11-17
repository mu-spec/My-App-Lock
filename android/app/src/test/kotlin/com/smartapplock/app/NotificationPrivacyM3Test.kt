package com.smartapplock.app

import com.smartapplock.app.NotificationPrivacyEngine.Posted
import com.smartapplock.app.NotificationPrivacyEngine.RemovalCause
import com.smartapplock.app.NotificationPrivacyPolicy.Mode
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 14 / M3: notification privacy floors from Security Profiles and Smart
 * Rules (owner decision "linked to levels": a rule/profile raising an app to
 * Critical -> Maximum privacy, Sensitive -> Hide content; never weaker than
 * the owner's per-app mode). Executes the shared vectors
 * `test/fixtures/notification_privacy/m3_profile_rule_vectors.json` through
 * the native path ([SmartRuleTransport.parse] -> [NotificationPrivacyPolicy]).
 * JVM only; not device evidence.
 */
class NotificationPrivacyM3Test {
    private val own = "com.smartapplock.app"
    private val bank = "com.bank.app"
    private val chat = "org.chat.app"
    private val game = "com.kids.game"
    private val other = "com.other.app"
    private val protectedSet = setOf(bank, chat, game)
    private val salt = ByteArray(16) { (it * 3).toByte() }
    private val everyDay = setOf(1, 2, 3, 4, 5, 6, 7)

    private fun allDay(level: SecurityLevel, vararg targets: String) =
        SmartRuleSpec(level, everyDay, allDay = true, start = 0, end = 0, targets = targets.toSet())

    private fun state(
        rules: Collection<SmartRuleSpec> = emptyList(),
        modes: Map<String, Mode> = mapOf(bank to Mode.MAXIMUM, chat to Mode.HIDE_CONTENT),
        protectedPackages: Set<String> = protectedSet,
        damaged: Boolean = false,
        enabled: Boolean = true,
        day: Int = 3,
        minute: Int = 600,
    ) = NotificationPrivacyPolicy.State(
        ownPackage = own,
        protectionEnabled = enabled,
        protectedPackages = protectedPackages,
        modes = modes,
        storeInvalid = false,
        ruleFloors = NotificationPrivacyPolicy.ruleFloors(rules, damaged, protectedPackages, day, minute),
        ruleTargeted = NotificationPrivacyPolicy.ruleTargeted(rules, damaged, protectedPackages),
    )

    @Test
    fun levelToFloorMappingIsTheOwnerDecision() {
        assertEquals(Mode.MAXIMUM, NotificationPrivacyPolicy.floorFor(SecurityLevel.CRITICAL))
        assertEquals(Mode.HIDE_CONTENT, NotificationPrivacyPolicy.floorFor(SecurityLevel.SENSITIVE))
        assertEquals(Mode.OFF, NotificationPrivacyPolicy.floorFor(SecurityLevel.STANDARD))
        assertEquals(Mode.OFF, NotificationPrivacyPolicy.floorFor(null))
    }

    @Test
    fun effectiveModeIsNeverWeakerThanThePerAppModeOrTheFloor() {
        val levels = listOf<SecurityLevel?>(null, SecurityLevel.STANDARD, SecurityLevel.SENSITIVE, SecurityLevel.CRITICAL)
        for (perApp in Mode.values()) for (level in levels) {
            val rules = if (level == null || level == SecurityLevel.STANDARD) emptyList() else listOf(allDay(level, game))
            val s = state(rules = rules, modes = if (perApp == Mode.OFF) emptyMap() else mapOf(game to perApp))
            val got = NotificationPrivacyPolicy.effectiveMode(s, game)
            val floor = NotificationPrivacyPolicy.floorFor(level)
            assertTrue("$perApp/$level", got.rank >= perApp.rank && got.rank >= floor.rank)
            assertEquals("$perApp/$level", maxOf(perApp.rank, floor.rank), got.rank)
        }
    }

    @Test
    fun theSavedBaselineLevelAloneImpliesNothing() {
        // No rule / Normal profile: only the per-app modes (M2 behaviour).
        val s = state()
        assertTrue(s.ruleFloors.isEmpty())
        assertEquals(Mode.OFF, NotificationPrivacyPolicy.effectiveMode(s, game))
        assertFalse(NotificationPrivacyPolicy.listenerWanted(state(modes = emptyMap())))
    }

    @Test
    fun floorsNeverApplyToUnprotectedAppsOwnAppOrDisabledProtection() {
        val rules = listOf(allDay(SecurityLevel.CRITICAL, other, own, game))
        assertEquals(mapOf(game to Mode.MAXIMUM), state(rules = rules).ruleFloors)
        assertEquals(Mode.OFF, NotificationPrivacyPolicy.effectiveMode(state(rules = rules), other))
        assertEquals(Mode.OFF, NotificationPrivacyPolicy.effectiveMode(state(rules = rules, protectedPackages = protectedSet + own), own))
        val disabled = state(rules = rules, enabled = false)
        assertEquals(Mode.OFF, NotificationPrivacyPolicy.effectiveMode(disabled, game))
        assertFalse(NotificationPrivacyPolicy.listenerWanted(disabled))
        assertTrue(NotificationPrivacyPolicy.raisedNow(disabled).isEmpty())
        // A rule that only names unprotected apps never binds the listener.
        assertFalse(NotificationPrivacyPolicy.listenerWanted(state(rules = listOf(allDay(SecurityLevel.CRITICAL, other)), modes = emptyMap())))
    }

    @Test
    fun aDamagedRuleStoreFailsClosedLikeTheLock() {
        val s = state(damaged = true, modes = emptyMap())
        for (pkg in protectedSet) assertEquals(Mode.MAXIMUM, NotificationPrivacyPolicy.effectiveMode(s, pkg))
        assertEquals(Mode.OFF, NotificationPrivacyPolicy.effectiveMode(s, other))
        assertEquals(protectedSet, s.ruleTargeted)
        assertTrue(NotificationPrivacyPolicy.listenerWanted(s))
    }

    @Test
    fun listenerStaysBoundForRuleTargetsOutsideTheirWindow() {
        val rule = SmartRuleSpec(SecurityLevel.SENSITIVE, setOf(1), allDay = false, start = 540, end = 600, targets = setOf(game))
        val s = state(rules = listOf(rule), modes = emptyMap(), day = 5)
        assertTrue(s.ruleFloors.isEmpty())
        assertTrue("bound so the window start is not missed", NotificationPrivacyPolicy.listenerWanted(s))
    }

    @Test
    fun raisedNowListsOnlyAppsWhereAProfileOrRuleIsStricter() {
        val rules = listOf(allDay(SecurityLevel.SENSITIVE, bank, chat, game, other))
        // bank per-app Maximum, chat per-app Hide content: not raised.
        assertEquals(mapOf(game to Mode.HIDE_CONTENT), NotificationPrivacyPolicy.raisedNow(state(rules = rules)))
    }

    @Test
    fun nextRuleCheckIsTheNextBoundaryCapped() {
        val rule = SmartRuleSpec(SecurityLevel.SENSITIVE, everyDay, allDay = false, start = 540, end = 1020, targets = setOf(game))
        assertEquals(31_000L, NotificationPrivacyPolicy.nextRuleCheckDelayMs(listOf(rule), 539, 30_000L))
        // Exactly at a boundary minute: the next one, never "now" again.
        assertEquals(NotificationPrivacyPolicy.MAX_RULE_CHECK_DELAY_MS, NotificationPrivacyPolicy.nextRuleCheckDelayMs(listOf(rule), 540, 0L))
        assertEquals(61_000L, NotificationPrivacyPolicy.nextRuleCheckDelayMs(listOf(rule), 1019, 0L))
        // After the last boundary: midnight (day change), capped at 15 min.
        assertEquals(60_000L - 59_999L + 1_000L, NotificationPrivacyPolicy.nextRuleCheckDelayMs(listOf(rule), 1439, 59_999L))
        assertEquals(NotificationPrivacyPolicy.MAX_RULE_CHECK_DELAY_MS, NotificationPrivacyPolicy.nextRuleCheckDelayMs(emptyList(), 10, 0L))
        assertTrue(NotificationPrivacyPolicy.nextRuleCheckDelayMs(listOf(rule), 539, 59_999L) >= 1_000L)
    }

    // ---- shared vectors (profiles + rules) ---------------------------------

    @Suppress("UNCHECKED_CAST")
    @Test
    fun sharedProfileAndRuleVectors() {
        val v = MiniJson.parse(locate("test/fixtures/notification_privacy/m3_profile_rule_vectors.json").readText()) as Map<String, Any?>
        val protectedPackages = (v["protected"] as List<String>).toSet()
        val perApp = (v["perApp"] as Map<String, String>).mapValues { Mode.fromId(it.value)!! }
        var checks = 0
        for (vector in v["vectors"] as List<Map<String, Any?>>) {
            val name = vector["name"] as String
            val transport = vector["transport"] as List<Any?>
            val rules = SmartRuleTransport.parse(1, transport)
            assertNotNull("$name: transport must parse natively", rules)
            for (c in vector["checks"] as List<Map<String, Any?>>) {
                val day = (c["day"] as Number).toInt()
                val minute = (c["minute"] as Number).toInt()
                for (order in listOf(rules!!.toList(), rules.toList().reversed())) {
                    val s = NotificationPrivacyPolicy.State(
                        own, true, protectedPackages, perApp, false,
                        NotificationPrivacyPolicy.ruleFloors(order, false, protectedPackages, day, minute),
                        NotificationPrivacyPolicy.ruleTargeted(order, false, protectedPackages),
                    )
                    val floors = (c["floors"] as Map<String, String>).mapValues { Mode.fromId(it.value)!! }
                    assertEquals("$name d$day m$minute floors", floors, s.ruleFloors)
                    for ((pkg, id) in c["effective"] as Map<String, String>) {
                        assertEquals("$name d$day m$minute $pkg", Mode.fromId(id), NotificationPrivacyPolicy.effectiveMode(s, pkg))
                    }
                }
                checks++
            }
        }
        assertEquals(17, checks)
    }

    // ---- engine: profile transitions and rule windows ----------------------

    private class FakePort(var state: NotificationPrivacyPolicy.State, val salt: ByteArray) : NotificationPrivacyEngine.Port {
        val cancelled = mutableListOf<String>()
        val posted = mutableListOf<NotificationPrivacyEngine.Placeholder>()
        override fun state() = state
        override fun placeholderTag(packageName: String) = NotificationPrivacyEngine.placeholderTag(salt, packageName)
        override fun appLabel(packageName: String) = packageName.split('.')[1].replaceFirstChar { it.uppercase() }
        override fun canPostPlaceholders(mode: Mode) = true
        override fun cancelSource(key: String): Boolean { cancelled += key; return true }
        override fun postPlaceholder(placeholder: NotificationPrivacyEngine.Placeholder): Boolean { posted += placeholder; return true }
    }

    private fun n(pkg: String, key: String, flags: Int = 0) = Posted(key, pkg, flags, sameUser = true)

    @Test
    fun profileTransitionsUpdateEffectivePrivacyImmediately() {
        // Normal: game Off (untouched), chat Hide content.
        val port = FakePort(state(), salt)
        val engine = NotificationPrivacyEngine(port)
        engine.onConnected(emptyList())
        val c1 = n(chat, "c1")
        engine.onPosted(n(game, "g0"))
        engine.onPosted(c1)
        engine.onRemoved(c1, RemovalCause.LISTENER)
        assertEquals(listOf("c1"), port.cancelled)
        assertEquals("Chat", port.posted.single().title)

        // Switch to Guest (configureProtection -> refreshBinding -> re-check):
        // the visible game original is removed at once and the chat
        // placeholder is re-rendered without the app name.
        port.state = state(rules = listOf(allDay(SecurityLevel.CRITICAL, bank, chat, game)))
        engine.onConfigurationChanged(listOf(n(game, "g0"), n(game, "g-ongoing", NotificationPrivacyEngine.FLAG_ONGOING_EVENT)))
        assertEquals(listOf("c1", "g0"), port.cancelled)
        assertEquals("New notification", port.posted.last().title)
        assertEquals(Mode.MAXIMUM, port.posted.last().mode)
        engine.onRemoved(n(game, "g0"), RemovalCause.LISTENER)
        assertEquals(Mode.MAXIMUM, port.posted.last().mode)
        assertEquals(game, port.posted.last().sourcePackage)

        // Back to Normal: never weakened in place; the next game notification
        // follows its per-app mode (Off -> untouched) again.
        val before = port.posted.size
        port.state = state()
        engine.onConfigurationChanged(emptyList())
        assertEquals(before, port.posted.size)
        engine.onPosted(n(game, "g1"))
        assertEquals(listOf("c1", "g0"), port.cancelled)
        // ...while chat keeps its per-app Hide content (no weaker than before).
        engine.onPosted(n(chat, "c2"))
        assertEquals(listOf("c1", "g0", "c2"), port.cancelled)
    }

    @Test
    fun ruleActivationAndExpiryThroughTheEngine() {
        val rule = SmartRuleSpec(SecurityLevel.CRITICAL, setOf(3), allDay = false, start = 600, end = 660, targets = setOf(game))
        val port = FakePort(state(rules = listOf(rule), minute = 599), salt)
        val engine = NotificationPrivacyEngine(port)
        engine.onConnected(listOf(n(game, "before")))
        assertTrue("before the window: untouched", port.cancelled.isEmpty())
        // Boundary timer fires at 10:00: the visible original is swept.
        port.state = state(rules = listOf(rule), minute = 600)
        engine.onConfigurationChanged(listOf(n(game, "before")))
        assertEquals(listOf("before"), port.cancelled)
        engine.onRemoved(n(game, "before"), RemovalCause.LISTENER)
        assertEquals(Mode.MAXIMUM, port.posted.single().mode)
        // 11:00 (end exclusive): expired; new game notifications are untouched,
        // the Maximum placeholder is not weakened.
        port.state = state(rules = listOf(rule), minute = 660)
        engine.onConfigurationChanged(emptyList())
        engine.onPosted(n(game, "after"))
        assertEquals(listOf("before"), port.cancelled)
        assertEquals(1, port.posted.size)
    }

    @Test
    fun conflictingRulesThroughTheEngineUseTheStrictest() {
        val rules = listOf(
            allDay(SecurityLevel.SENSITIVE, game),
            SmartRuleSpec(SecurityLevel.CRITICAL, setOf(3), allDay = false, start = 600, end = 660, targets = setOf(game)),
        )
        for (order in listOf(rules, rules.reversed())) {
            val port = FakePort(state(rules = order, minute = 630), salt)
            val engine = NotificationPrivacyEngine(port)
            engine.onConnected(emptyList())
            engine.onPosted(n(game, "g"))
            engine.onRemoved(n(game, "g"), RemovalCause.LISTENER)
            assertEquals(Mode.MAXIMUM, port.posted.single().mode)
            assertEquals("New notification", port.posted.single().title)
        }
    }

    @Test
    fun ruleFloorsKeepTheM2Protections() {
        // Recursion, ongoing and other-user rules hold under a Guest floor.
        val port = FakePort(state(rules = listOf(allDay(SecurityLevel.CRITICAL, bank, chat, game, own)), protectedPackages = protectedSet + own), salt)
        val engine = NotificationPrivacyEngine(port)
        engine.onConnected(emptyList())
        engine.onPosted(n(own, "fgs"))
        engine.onPosted(Posted("ph", own, 0, true, NotificationPrivacyEngine.placeholderTag(salt, game)))
        engine.onPosted(n(game, "ongoing", NotificationPrivacyEngine.FLAG_FOREGROUND_SERVICE))
        engine.onPosted(Posted("wp", game, 0, sameUser = false))
        engine.onPosted(n(other, "o"))
        assertTrue(port.cancelled.isEmpty())
        // Duplicates: three game messages -> one placeholder.
        for (k in listOf("a", "b", "c")) {
            engine.onPosted(n(game, k))
            engine.onRemoved(n(game, k), RemovalCause.LISTENER)
        }
        assertEquals(1, port.posted.size)
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

    // Same minimal JSON reader as SmartRuleParityVectorsTest (kept private there).
    private object MiniJson {
        fun parse(text: String): Any? {
            val p = P(text)
            val value = p.value()
            p.ws()
            check(p.i == text.length) { "trailing data at ${p.i}" }
            return value
        }

        private class P(val s: String) {
            var i = 0
            fun ws() {
                while (i < s.length && s[i].isWhitespace()) i++
            }

            fun value(): Any? {
                ws()
                return when (val c = s[i]) {
                    '{' -> obj()
                    '[' -> arr()
                    '"' -> str()
                    't' -> lit("true", true)
                    'f' -> lit("false", false)
                    'n' -> lit("null", null)
                    else -> if (c == '-' || c.isDigit()) num() else error("unexpected '$c' at $i")
                }
            }

            private fun lit(word: String, v: Any?): Any? {
                check(s.startsWith(word, i)) { "bad literal at $i" }
                i += word.length
                return v
            }

            private fun obj(): Map<String, Any?> {
                val out = LinkedHashMap<String, Any?>()
                i++
                ws()
                if (s[i] == '}') { i++; return out }
                while (true) {
                    ws()
                    val k = str()
                    ws(); check(s[i] == ':'); i++
                    out[k] = value()
                    ws()
                    if (s[i] == ',') { i++; continue }
                    check(s[i] == '}') { "expected } at $i" }
                    i++
                    return out
                }
            }

            private fun arr(): List<Any?> {
                val out = ArrayList<Any?>()
                i++
                ws()
                if (s[i] == ']') { i++; return out }
                while (true) {
                    out += value()
                    ws()
                    if (s[i] == ',') { i++; continue }
                    check(s[i] == ']') { "expected ] at $i" }
                    i++
                    return out
                }
            }

            private fun str(): String {
                check(s[i] == '"') { "expected string at $i" }
                i++
                val b = StringBuilder()
                while (s[i] != '"') {
                    if (s[i] == '\\') {
                        i++
                        when (val e = s[i]) {
                            'n' -> b.append('\n'); 't' -> b.append('\t'); 'r' -> b.append('\r')
                            'b' -> b.append('\b'); 'f' -> b.append('\u000c')
                            'u' -> { b.append(s.substring(i + 1, i + 5).toInt(16).toChar()); i += 4 }
                            else -> b.append(e)
                        }
                    } else {
                        b.append(s[i])
                    }
                    i++
                }
                i++
                return b.toString()
            }

            /** Integer literals → Int (or Long); anything with . or e → Double. */
            private fun num(): Number {
                val start = i
                if (s[i] == '-') i++
                while (i < s.length && (s[i].isDigit() || s[i] in ".eE+-")) i++
                val t = s.substring(start, i)
                if (t.any { it in ".eE" }) return t.toDouble()
                val l = t.toLong()
                return if (l in Int.MIN_VALUE..Int.MAX_VALUE) l.toInt() else l
            }
        }
    }
}
