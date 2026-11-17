package com.smartapplock.app

import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.KeyStore
import java.util.concurrent.Executors
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * P13/M3 Batch 2: `smart_app_lock/key_wrap` — AndroidKeyStore KEK for the
 * settings data key (K-2+B-compat). Methods: `wrapNew {key}` →
 * `{alias, blob}`, `unwrap {alias, blob}` → key (base64). Errors are
 * reported as codes only (never key material). There is NO delete method:
 * KEK aliases are never removed by the app. Keystore work runs off the main
 * thread. On-device behaviour (alias isolation, StrongBox/TEE, backup
 * exclusion) is DEVICE BLOCKED on host.
 */
object KeyWrapChannel {
    const val CHANNEL = "smart_app_lock/key_wrap"
    private val executor = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    fun register(engine: FlutterEngine) {
        val core = KeyWrapCore(AndroidKeyStoreKekStore())
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "wrapNew" -> {
                    val key = call.argument<String>("key")
                    if (key == null) {
                        result.error("malformed", null, null)
                        return@setMethodCallHandler
                    }
                    executor.execute {
                        try {
                            val raw = Base64.decode(key, Base64.NO_WRAP)
                            val w = core.wrapNew(raw)
                            raw.fill(0)
                            val out = mapOf("alias" to w.alias, "blob" to Base64.encodeToString(w.blob, Base64.NO_WRAP))
                            main.post { result.success(out) }
                        } catch (e: KeyWrapException) {
                            main.post { result.error(e.code, null, null) }
                        } catch (e: Exception) {
                            main.post { result.error("malformed", null, null) }
                        }
                    }
                }
                "unwrap" -> {
                    val alias = call.argument<String>("alias")
                    val blob = call.argument<String>("blob")
                    if (alias == null || blob == null) {
                        result.error("malformed", null, null)
                        return@setMethodCallHandler
                    }
                    executor.execute {
                        try {
                            val k = core.unwrap(alias, Base64.decode(blob, Base64.NO_WRAP))
                            val out = Base64.encodeToString(k, Base64.NO_WRAP)
                            k.fill(0)
                            main.post { result.success(out) }
                        } catch (e: KeyWrapException) {
                            main.post { result.error(e.code, null, null) }
                        } catch (e: Exception) {
                            main.post { result.error("malformed", null, null) }
                        }
                    }
                }
                else -> result.notImplemented()
            }
        }
    }
}

/** Non-exportable AES-256 KEKs in AndroidKeyStore. Never deletes. */
class AndroidKeyStoreKekStore : KekStore {
    private fun ks(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    override fun contains(alias: String): Boolean = ks().containsAlias(alias)

    override fun create(alias: String): SecretKey {
        if (contains(alias)) throw KeyWrapException("alias_collision")
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        gen.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return gen.generateKey()
    }

    override fun get(alias: String): SecretKey? = ks().getKey(alias, null) as SecretKey?

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
    }
}
