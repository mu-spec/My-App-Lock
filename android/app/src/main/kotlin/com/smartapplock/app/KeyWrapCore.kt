package com.smartapplock.app

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * P13/M3 Batch 2 (F-KEY-1, K-2+B-compat): wraps the settings data key under
 * a non-exportable key-encryption key (KEK). Pure JVM logic so it is unit
 * testable; [KekStore] is AndroidKeyStore in production.
 *
 * Rules:
 *  * every wrap creates a NEW KEK under a fresh random alias (two instances
 *    can never overwrite each other's KEK);
 *  * nothing here ever deletes a KEK (no delete operation exists);
 *  * blob = iv(12) || ciphertext || tag(16), AES-256-GCM.
 */
interface KekStore {
    fun contains(alias: String): Boolean
    /** Creates a new KEK; must fail if [alias] already exists. */
    fun create(alias: String): SecretKey
    fun get(alias: String): SecretKey?
}

class KeyWrapException(val code: String, cause: Throwable? = null) : Exception(code, cause)

class KeyWrapCore(
    private val store: KekStore,
    private val random: SecureRandom = SecureRandom(),
) {
    data class Wrapped(val alias: String, val blob: ByteArray)

    fun newAlias(): String {
        val b = ByteArray(8).also { random.nextBytes(it) }
        return ALIAS_PREFIX + b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    fun wrapNew(key: ByteArray): Wrapped {
        if (key.size != DATA_KEY_BYTES) throw KeyWrapException("bad_key")
        var alias = newAlias()
        var tries = 0
        while (store.contains(alias)) {
            if (++tries >= 4) throw KeyWrapException("alias_collision")
            alias = newAlias()
        }
        try {
            val kek = store.create(alias)
            val c = Cipher.getInstance(TRANSFORMATION)
            c.init(Cipher.ENCRYPT_MODE, kek) // provider-generated IV
            val iv = c.iv ?: throw KeyWrapException("no_iv")
            if (iv.size != IV_BYTES) throw KeyWrapException("bad_iv")
            return Wrapped(alias, iv + c.doFinal(key))
        } catch (e: KeyWrapException) {
            throw e
        } catch (e: Exception) {
            throw KeyWrapException("keystore_error", e)
        }
    }

    fun unwrap(alias: String, blob: ByteArray): ByteArray {
        if (!alias.startsWith(ALIAS_PREFIX) || blob.size < IV_BYTES + TAG_BYTES) {
            throw KeyWrapException("malformed")
        }
        val kek = try {
            store.get(alias)
        } catch (e: Exception) {
            throw KeyWrapException("keystore_error", e)
        } ?: throw KeyWrapException(KEY_MISSING)
        try {
            val c = Cipher.getInstance(TRANSFORMATION)
            c.init(Cipher.DECRYPT_MODE, kek, GCMParameterSpec(TAG_BYTES * 8, blob, 0, IV_BYTES))
            val out = c.doFinal(blob, IV_BYTES, blob.size - IV_BYTES)
            if (out.size != DATA_KEY_BYTES) throw KeyWrapException("unwrap_failed")
            return out
        } catch (e: KeyWrapException) {
            throw e
        } catch (e: Exception) {
            throw KeyWrapException("unwrap_failed", e)
        }
    }

    companion object {
        const val ALIAS_PREFIX = "sal_kek_"
        const val KEY_MISSING = "key_missing"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val DATA_KEY_BYTES = 32
        const val IV_BYTES = 12
        const val TAG_BYTES = 16
    }
}
