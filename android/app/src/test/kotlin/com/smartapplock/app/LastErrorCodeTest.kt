package com.smartapplock.app

import android.content.Context
import android.content.SharedPreferences
import com.smartapplock.app.NativeDurabilityRegressionTest.Ctx
import com.smartapplock.app.NativeDurabilityRegressionTest.Mode
import com.smartapplock.app.NativeDurabilityRegressionTest.Prefs
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * P13/M3 NF-RG-1: allowlisted last-error codes. SIMULATED (JVM): host
 * evidence only, not device QA (DQ-LOG-3 stays DEVICE BLOCKED).
 * IDs follow m3_security_decisions/D section 7 (KE / RE / DG).
 */
class LastErrorCodeTest {
    private val codeKey = "last_error_code"
    private val textKey = "last_error"

    private val canaries = listOf(
        "com.canary.protected.pkg",
        "challenge-7f3a",
        "at com.smartapplock.X(X.kt:1)",
        "\n\tat ",
        "x".repeat(4096),
        "\u202Eטקסט عربي 中文",
        "enc:v1:AAAA",
        "%s%n",
    )

    private fun allowlisted(prefs: Prefs) {
        val code = prefs.data[codeKey]
        val text = prefs.data[textKey]
        if (code == null && text == null) return
        val decoded = LastErrorCode.decode(code as String)
        assertNotNull(decoded)
        assertEquals("code key must be canonical", LastErrorCode.encode(decoded!!), code)
        assertEquals("text key must be the code's neutral text", decoded.neutralText, text)
    }

    private fun noCanary(prefs: Prefs) {
        for (store in listOf(prefs.data, prefs.disk)) {
            for ((_, v) in store) {
                val s = v.toString()
                for (c in canaries) {
                    assertFalse("canary leaked: ${c.take(24)}", s.contains(c))
                }
                assertFalse("message leaked", s.contains("Watcher start failed:"))
            }
        }
    }

    // ---------------------------------------------------------------- KE-1
    @Test
    fun `KE-1 W6 watcher-start failures with canary messages persist only a code`() {
        for (canary in canaries) {
            for (e in listOf<Throwable>(
                IllegalStateException(canary),
                SecurityException(canary),
                RuntimeException(canary, IllegalArgumentException(canary)),
                android.app.ForegroundServiceStartNotAllowedException(canary),
            )) {
                val ctx = Ctx()
                ProtectionStateStore.setLastError(ctx, LastErrorCode.forWatcherStart(e, 34))
                noCanary(ctx.prefs)
                allowlisted(ctx.prefs)
                val shown = ProtectionStateStore.lastError(ctx)!!
                assertFalse(shown.contains(canary))
            }
        }
    }

    @Test
    fun `KE-1 W3 channel failures and legacy raw canaries never survive a read`() {
        for (canary in canaries) {
            val ctx = Ctx()
            // W3 call site passes the constant (KE-6 proves the source).
            ProtectionStateStore.setLastError(ctx, LastErrorCode.CHANNEL_CALL_FAILED)
            noCanary(ctx.prefs)
            allowlisted(ctx.prefs)
            // Legacy install: raw W3/W6 text persisted by 6110ff8.
            val legacy = Ctx()
            legacy.prefs.data[textKey] = canary
            legacy.prefs.disk[textKey] = canary
            assertEquals(LastErrorCode.UNKNOWN, ProtectionStateStore.lastErrorCode(legacy))
            noCanary(legacy.prefs) // overwritten in memory AND flushed to disk
            allowlisted(legacy.prefs)
            val legacyW6 = Ctx()
            legacyW6.prefs.data[textKey] = "Watcher start failed: $canary"
            assertEquals(LastErrorCode.UNKNOWN.neutralText, ProtectionStateStore.lastError(legacyW6))
            noCanary(legacyW6.prefs)
        }
    }

    // ---------------------------------------------------------------- KE-2
    @Test
    fun `KE-2 encode-decode round trip for every code, wires unique and bounded`() {
        assertEquals(10, LastErrorCode.entries.size)
        assertEquals(LastErrorCode.entries.size, LastErrorCode.entries.map { it.wire }.toSet().size)
        assertEquals(LastErrorCode.entries.size, LastErrorCode.entries.map { it.neutralText }.toSet().size)
        for (c in LastErrorCode.entries) {
            assertEquals(c, LastErrorCode.decode(LastErrorCode.encode(c)))
            assertTrue(Regex("^[a-z_]{1,40}$").matches(c.wire))
        }
    }

    // ---------------------------------------------------------------- KE-3
    @Test
    fun `KE-3 decode never echoes and maps every malformed value to UNKNOWN`() {
        assertNull(LastErrorCode.decode(null))
        val bad = listOf(
            "", "v1:", "v2:x", "v1:UNKNOWN_UPPER", "v1:" + "a".repeat(41), "v1:x\n",
            "v1:../x", "v1:watcher_interrupted ", " v1:watcher_interrupted",
            "v1:watcher_interrupted\u0000", "watcher_interrupted",
            WatcherTeardownPolicy.INTERRUPTED_MESSAGE, "v1:not_a_code",
        ) + canaries
        for (b in bad) {
            assertEquals("decode(${b.take(20)})", LastErrorCode.UNKNOWN, LastErrorCode.decode(b))
        }
    }

    // ---------------------------------------------------------------- KE-4
    @Test
    fun `KE-4 clear-on-start only for WATCHER_INTERRUPTED, legacy sentence migrated first`() {
        val ctx = Ctx()
        ctx.prefs.data[textKey] = WatcherTeardownPolicy.INTERRUPTED_MESSAGE // 6110ff8 value
        val code = ProtectionStateStore.lastErrorCode(ctx)
        assertEquals(LastErrorCode.WATCHER_INTERRUPTED, code)
        assertEquals("v1:watcher_interrupted", ctx.prefs.data[codeKey])
        assertTrue(WatcherTeardownPolicy.clearsLastErrorOnStart(code))
        for (other in LastErrorCode.entries - LastErrorCode.WATCHER_INTERRUPTED) {
            assertFalse(WatcherTeardownPolicy.clearsLastErrorOnStart(other))
        }
        assertFalse(WatcherTeardownPolicy.clearsLastErrorOnStart(null))
    }

    // ---------------------------------------------------------------- KE-5
    @Test
    fun `KE-5 watcher-start code is selected by exception class and SDK only`() {
        assertEquals(LastErrorCode.WATCHER_START_NOT_ALLOWED,
            LastErrorCode.forWatcherStart(SecurityException("x"), 28))
        assertEquals(LastErrorCode.WATCHER_START_FAILED,
            LastErrorCode.forWatcherStart(IllegalStateException("x"), 34))
        assertEquals(LastErrorCode.WATCHER_START_NOT_ALLOWED,
            LastErrorCode.forWatcherStart(android.app.ForegroundServiceStartNotAllowedException("x"), 31))
        // Below API 31 the class is never consulted (not linked on Android 9).
        assertEquals(LastErrorCode.WATCHER_START_FAILED,
            LastErrorCode.forWatcherStart(android.app.ForegroundServiceStartNotAllowedException("x"), 30))
        // The message cannot steer the choice.
        assertEquals(LastErrorCode.WATCHER_START_FAILED,
            LastErrorCode.forWatcherStart(IllegalStateException("SecurityException not allowed"), 34))
    }

    // ---------------------------------------------------------------- KE-6
    @Test
    fun `KE-6 every setLastError call passes an allowlisted constant, null or a class selector`() {
        val dir = listOf(
            File("src/main/kotlin/com/smartapplock/app"),
            File("android/app/src/main/kotlin/com/smartapplock/app"),
        ).first { it.isDirectory }
        val allowed = Regex(
            """^(null|it|LastErrorCode\.[A-Z_]+|LastErrorCode\.forWatcherStart\(e\))$""",
        )
        var calls = 0
        for (f in dir.listFiles()!!.filter { it.name.endsWith(".kt") }) {
            val src = f.readText()
            var i = src.indexOf("setLastError(")
            while (i >= 0) {
                val isDecl = src.substring(maxOf(0, i - 4), i) == "fun "
                var depth = 0
                var j = i + "setLastError".length
                val start = j + 1
                while (true) {
                    val ch = src[j]
                    if (ch == '(') depth++
                    if (ch == ')') { depth--; if (depth == 0) break }
                    j++
                }
                if (!isDecl) {
                    calls++
                    val args = src.substring(start, j)
                    val second = args.substringAfter(",").trim().trimEnd(',').trim()
                    for (bad in listOf("message", "toString", "localizedMessage", "stackTrace", "$", "\"")) {
                        assertFalse("${f.name}: setLastError arg contains $bad", second.contains(bad))
                    }
                    assertTrue("${f.name}: setLastError arg '$second'", allowed.matches(second))
                }
                i = src.indexOf("setLastError(", j)
            }
        }
        // 1 store + 1 boot + 1 channel + 7 service + 4 store-internal (null/it) sites.
        assertTrue("found $calls calls", calls >= 10)
        val store = File(dir, "ProtectionStateStore.kt").readText()
        assertFalse(store.contains("fun setLastError(context: Context, message: String"))
    }

    // ---------------------------------------------------------------- KE-7
    @Test
    fun `KE-7 reconciliation matrix covers all five branches`() {
        // 1 nothing stored
        assertNull(ProtectionStateStore.lastErrorCode(Ctx()))
        // 2 legacy text only -> exact map + persist
        val legacy = Ctx().also { it.prefs.data[textKey] = "Protection service could not restart after boot." }
        assertEquals(LastErrorCode.BOOT_RESTART_FAILED, ProtectionStateStore.lastErrorCode(legacy))
        assertEquals("v1:boot_restart_failed", legacy.prefs.data[codeKey])
        val levels = Ctx().also { it.prefs.data[textKey] = ProtectionStateStore.ERROR_LEVELS_INVALID }
        assertEquals(LastErrorCode.SECURITY_LEVELS_INVALID, ProtectionStateStore.lastErrorCode(levels))
        allowlisted(levels.prefs)
        // 3 code without text (an older build cleared last_error) -> cleared
        val cleared = Ctx().also { it.prefs.data[codeKey] = "v1:overlay_unavailable" }
        assertNull(ProtectionStateStore.lastErrorCode(cleared))
        assertFalse(cleared.prefs.data.containsKey(codeKey))
        // 4 consistent pair
        val ok = Ctx()
        ProtectionStateStore.setLastError(ok, LastErrorCode.OVERLAY_UNAVAILABLE)
        assertEquals(LastErrorCode.OVERLAY_UNAVAILABLE, ProtectionStateStore.lastErrorCode(ok))
        // 5 text changed by an older build -> the TEXT wins, the stale code never
        val changed = Ctx()
        ProtectionStateStore.setLastError(changed, LastErrorCode.OVERLAY_UNAVAILABLE)
        changed.prefs.data[textKey] = "Watcher start failed: com.canary.protected.pkg"
        assertEquals(LastErrorCode.UNKNOWN, ProtectionStateStore.lastErrorCode(changed))
        noCanary(changed.prefs)
        allowlisted(changed.prefs)
        val changedKnown = Ctx()
        ProtectionStateStore.setLastError(changedKnown, LastErrorCode.OVERLAY_UNAVAILABLE)
        changedKnown.prefs.data[textKey] = WatcherTeardownPolicy.INTERRUPTED_MESSAGE
        assertEquals(LastErrorCode.WATCHER_INTERRUPTED, ProtectionStateStore.lastErrorCode(changedKnown))
        // non-canonical code key with consistent-looking text is rewritten
        val odd = Ctx().also {
            it.prefs.data[codeKey] = "v1:../x"
            it.prefs.data[textKey] = LastErrorCode.UNKNOWN.neutralText
        }
        assertEquals(LastErrorCode.UNKNOWN, ProtectionStateStore.lastErrorCode(odd))
        assertEquals("v1:unknown", odd.prefs.data[codeKey])
    }

    // ---------------------------------------------------------------- KE-8
    // Added after mutation pass 1 (ME-5b SURVIVED): legacy mapping is EXACT.
    @Test
    fun `KE-8 legacy near-miss text maps to UNKNOWN, never to a neighbouring code`() {
        for (c in LastErrorCode.entries - LastErrorCode.UNKNOWN) {
            for (near in listOf(
                c.neutralText + " com.canary.protected.pkg",
                c.neutralText.take(10),
                c.neutralText.dropLast(1),
                c.neutralText.uppercase(),
                " " + c.neutralText,
                c.wire,
            )) {
                if (near == ProtectionStateStore.ERROR_LEVELS_INVALID) continue // exact legacy value
                assertEquals("fromLegacy(${near.take(24)})", LastErrorCode.UNKNOWN, LastErrorCode.fromLegacy(near))
            }
        }
        assertEquals(LastErrorCode.UNKNOWN, LastErrorCode.fromLegacy("Protection service could not start: x"))
        assertEquals(LastErrorCode.UNKNOWN, LastErrorCode.fromLegacy("Watcher start failed: x"))
    }

    // ---------------------------------------------------------------- RE-1..4
    @Test
    fun `RE-1 a restart reads the same code`() {
        val ctx = Ctx()
        ProtectionStateStore.setLastError(ctx, LastErrorCode.CHALLENGE_LAUNCH_BLOCKED)
        assertEquals(LastErrorCode.CHALLENGE_LAUNCH_BLOCKED, ProtectionStateStore.lastErrorCode(ctx.restarted()))
    }

    @Test
    fun `RE-2 wrong-typed prefs fail to UNKNOWN, both keys rewritten, no crash`() {
        for (key in listOf(codeKey, textKey)) {
            val prefs = TypedPrefs().also { it.data[key] = 42L }
            val ctx = TypedCtx(prefs)
            assertEquals(LastErrorCode.UNKNOWN, ProtectionStateStore.lastErrorCode(ctx))
            assertEquals("v1:unknown", prefs.data[codeKey])
            assertEquals(LastErrorCode.UNKNOWN.neutralText, prefs.data[textKey])
        }
    }

    @Test
    fun `RE-3 death after apply before flush leaves a stale or absent but allowlisted value`() {
        val ctx = Ctx()
        ProtectionStateStore.setLastError(ctx, LastErrorCode.WATCHER_INTERRUPTED)
        ctx.prefs.plan(Mode.FAIL_BEFORE_DISK)
        ProtectionStateStore.setLastError(ctx, null) // restart cleared it, never flushed
        val after = ctx.restarted()
        assertEquals(LastErrorCode.WATCHER_INTERRUPTED, ProtectionStateStore.lastErrorCode(after))
        allowlisted(after.prefs)
        val fresh = Ctx()
        fresh.prefs.plan(Mode.FAIL_BEFORE_DISK)
        ProtectionStateStore.setLastError(fresh, LastErrorCode.OVERLAY_UNAVAILABLE)
        assertNull(ProtectionStateStore.lastErrorCode(fresh.restarted()))
    }

    @Test
    fun `RE-4 both keys reach disk in ONE commit (never a mixed pair)`() {
        val ctx = Ctx()
        ProtectionStateStore.setLastError(ctx, LastErrorCode.WATCHER_INTERRUPTED)
        ctx.prefs.plan(Mode.OK, Mode.FAIL_BEFORE_DISK)
        ProtectionStateStore.setLastError(ctx, LastErrorCode.BOOT_RESTART_FAILED)
        val disk = ctx.prefs.disk
        val code = LastErrorCode.decode(disk[codeKey] as String?)
        assertNotNull(code)
        assertEquals(code!!.neutralText, disk[textKey])
        ctx.prefs.plan(Mode.OK, Mode.FAIL_BEFORE_DISK)
        ProtectionStateStore.setLastError(ctx, null)
        assertEquals(disk.containsKey(codeKey), disk.containsKey(textKey))
    }

    // ---------------------------------------------------------------- DG-1
    @Test
    fun `DG-1 downgrade writer and downgrade clear are reconciled`() {
        val ctx = Ctx()
        ProtectionStateStore.setLastError(ctx, LastErrorCode.WATCHER_INTERRUPTED)
        // 6110ff8 (old build) writes raw W6 text and leaves the code key.
        ctx.prefs.data[textKey] = "Watcher start failed: challenge-7f3a"
        assertEquals(LastErrorCode.UNKNOWN, ProtectionStateStore.lastErrorCode(ctx))
        noCanary(ctx.prefs)
        // The old build clears (removes last_error only).
        ProtectionStateStore.setLastError(ctx, LastErrorCode.WATCHER_INTERRUPTED)
        ctx.prefs.data.remove(textKey)
        assertNull(ProtectionStateStore.lastErrorCode(ctx))
        assertFalse(ctx.prefs.data.containsKey(codeKey))
        // An old build reading the new pair sees a neutral sentence.
        ProtectionStateStore.setLastError(ctx, LastErrorCode.CHANNEL_CALL_FAILED)
        assertEquals(LastErrorCode.CHANNEL_CALL_FAILED.neutralText, ctx.prefs.data[textKey])
    }

    // -- wrong-typed prefs (RE-2): getString throws like AOSP on a type clash
    class TypedPrefs : SharedPreferences {
        val data = mutableMapOf<String, Any>()
        override fun getBoolean(key: String?, defValue: Boolean) = data[key] as? Boolean ?: defValue
        override fun getLong(key: String?, defValue: Long) = data[key] as? Long ?: defValue
        override fun getInt(key: String?, defValue: Int) = data[key] as? Int ?: defValue
        override fun getString(key: String?, defValue: String?): String? {
            val v = data[key] ?: return defValue
            return v as String // ClassCastException on a type clash
        }
        override fun getStringSet(key: String?, defValues: Set<String>?): Set<String>? = defValues
        override fun contains(key: String?) = data.containsKey(key)
        override fun edit(): SharedPreferences.Editor = TypedEditor(this)
    }

    class TypedEditor(private val prefs: TypedPrefs) : SharedPreferences.Editor {
        private val puts = mutableMapOf<String, Any>()
        private val removes = mutableSetOf<String>()
        private fun put(key: String?, value: Any): SharedPreferences.Editor { puts[key!!] = value; return this }
        override fun putBoolean(key: String?, value: Boolean) = put(key, value)
        override fun putLong(key: String?, value: Long) = put(key, value)
        override fun putInt(key: String?, value: Int) = put(key, value)
        override fun putString(key: String?, value: String?) = put(key, value!!)
        override fun putStringSet(key: String?, values: Set<String>?) = put(key, values!!)
        override fun remove(key: String?): SharedPreferences.Editor { removes += key!!; return this }
        override fun clear(): SharedPreferences.Editor { prefs.data.clear(); return this }
        override fun apply() { commit() }
        override fun commit(): Boolean { removes.forEach { prefs.data.remove(it) }; prefs.data.putAll(puts); return true }
    }

    class TypedCtx(private val prefs: TypedPrefs) : Context() {
        override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences = prefs
    }
}
