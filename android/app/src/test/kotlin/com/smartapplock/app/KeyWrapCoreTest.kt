package com.smartapplock.app

import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * P13/M3 Batch 2: KeyWrapCore over a software KEK store (JVM). SIMULATED:
 * AndroidKeyStore itself (non-exportability, alias isolation, backup
 * exclusion) is DEVICE BLOCKED on host.
 */
class KeyWrapCoreTest {
    private class SoftStore : KekStore {
        val keys = LinkedHashMap<String, SecretKey>()
        var createCalls = 0
        override fun contains(alias: String) = keys.containsKey(alias)
        override fun create(alias: String): SecretKey {
            createCalls++
            check(!keys.containsKey(alias)) { "alias exists" }
            val k = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
            keys[alias] = k
            return k
        }
        override fun get(alias: String): SecretKey? = keys[alias]
    }

    private val dataKey = ByteArray(32) { (it * 7).toByte() }

    @Test
    fun `KW-1 wrap then unwrap returns the exact data key`() {
        val store = SoftStore()
        val core = KeyWrapCore(store)
        val w = core.wrapNew(dataKey)
        assertTrue(w.alias.startsWith(KeyWrapCore.ALIAS_PREFIX))
        assertEquals(KeyWrapCore.IV_BYTES + 32 + KeyWrapCore.TAG_BYTES, w.blob.size)
        assertArrayEquals(dataKey, core.unwrap(w.alias, w.blob))
    }

    @Test
    fun `KW-2 every wrap uses a NEW alias and never replaces an existing KEK`() {
        val store = SoftStore()
        val core = KeyWrapCore(store)
        val a = core.wrapNew(dataKey)
        val b = core.wrapNew(dataKey)
        assertNotEquals(a.alias, b.alias)
        assertEquals(2, store.keys.size)
        assertArrayEquals(dataKey, core.unwrap(a.alias, a.blob))
        assertArrayEquals(dataKey, core.unwrap(b.alias, b.blob))
    }

    @Test
    fun `KW-3 a missing KEK is reported as key_missing`() {
        val core = KeyWrapCore(SoftStore())
        try {
            core.unwrap(KeyWrapCore.ALIAS_PREFIX + "0011223344556677", ByteArray(60))
            fail()
        } catch (e: KeyWrapException) {
            assertEquals(KeyWrapCore.KEY_MISSING, e.code)
        }
    }

    @Test
    fun `KW-4 a tampered blob fails authentication (never returns bytes)`() {
        val store = SoftStore()
        val core = KeyWrapCore(store)
        val w = core.wrapNew(dataKey)
        val bad = w.blob.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() }
        try {
            core.unwrap(w.alias, bad)
            fail()
        } catch (e: KeyWrapException) {
            assertEquals("unwrap_failed", e.code)
        }
    }

    @Test
    fun `KW-5 malformed input and wrong key size are rejected without a KEK`() {
        val store = SoftStore()
        val core = KeyWrapCore(store)
        try { core.wrapNew(ByteArray(16)); fail() } catch (e: KeyWrapException) { assertEquals("bad_key", e.code) }
        try { core.unwrap("other_alias", ByteArray(60)); fail() } catch (e: KeyWrapException) { assertEquals("malformed", e.code) }
        try { core.unwrap(KeyWrapCore.ALIAS_PREFIX + "00", ByteArray(5)); fail() } catch (e: KeyWrapException) { assertEquals("malformed", e.code) }
        assertEquals(0, store.createCalls)
    }

    @Test
    fun `KW-6 alias collisions retry with a fresh alias and never overwrite`() {
        val store = SoftStore()
        // Deterministic random: first two aliases collide with existing KEKs.
        val fixed = object : SecureRandom() {
            var n = 0
            override fun nextBytes(bytes: ByteArray) { bytes.fill((if (n++ < 2) 0 else n).toByte()) }
        }
        val core = KeyWrapCore(store, fixed)
        val taken = KeyWrapCore.ALIAS_PREFIX + "0000000000000000"
        store.create(taken)
        val before = store.keys[taken]
        val w = core.wrapNew(dataKey)
        assertNotEquals(taken, w.alias)
        assertTrue(store.keys[taken] === before)
    }

    @Test
    fun `KW-7 the core exposes no delete operation (aliases are never removed)`() {
        val names = KeyWrapCore::class.java.declaredMethods.map { it.name.lowercase() } +
            KekStore::class.java.declaredMethods.map { it.name.lowercase() }
        assertFalse(names.any { it.contains("delete") || it.contains("remove") || it.contains("clear") })
    }
}
