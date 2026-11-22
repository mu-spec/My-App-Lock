package com.smartapplock.app

import android.os.Build
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.KeyStore
import java.security.SecureRandom
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Phase 18 / M1F (F18-3, owner-approved Option B):
 * `smart_app_lock/biometric_binding`.
 *
 *  * `createKey` → Boolean: replaces the AES-256-GCM key [BiometricBindingPolicy.ALIAS]
 *    (user authentication required for EVERY use, invalidated by a new
 *    biometric enrollment). False when Android refuses (no Class 3
 *    biometric, no secure lock screen, keystore error).
 *  * `checkKey` → `valid` / `invalidated` / `missing` / `error`.
 *  * `deleteKey`: best effort.
 *  * `authenticate {reason, requireConfirmation}` → true, or an error code:
 *    BiometricPrompt + CryptoObject over the key, BIOMETRIC_STRONG only; a
 *    device credential is never allowed. Success only when the
 *    authenticated cipher completes an encryption.
 *
 * Codes only, never key material or platform text; no logging (RL-01).
 * On-device behaviour (TEE/StrongBox, OEM enrollment handling, invalidation
 * timing) is DEVICE PENDING; host evidence is compile + JVM policy tests.
 */
object BiometricBindingChannel {
    const val CHANNEL = "smart_app_lock/biometric_binding"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val PROMPT_TITLE = "Smart App Lock"
    private const val NEGATIVE_LABEL = "Use app PIN or pattern"

    private val background = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val mainExecutor = Executor { main.post(it) }
    private val inProgress = AtomicBoolean(false)

    fun register(engine: FlutterEngine, activity: FragmentActivity) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "createKey" -> {
                    val strong = BiometricManager.from(activity)
                        .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                        BiometricManager.BIOMETRIC_SUCCESS
                    if (!strong) {
                        result.success(false)
                    } else {
                        background.execute {
                            val ok = createKey()
                            main.post { result.success(ok) }
                        }
                    }
                }
                "checkKey" -> background.execute {
                    val state = checkKey()
                    main.post { result.success(state) }
                }
                "deleteKey" -> background.execute {
                    deleteKey()
                    main.post { result.success(null) }
                }
                "authenticate" -> authenticate(
                    activity,
                    call.argument<String>("reason") ?: "",
                    call.argument<Boolean>("requireConfirmation") ?: true,
                    result,
                )
                else -> result.notImplemented()
            }
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun createKey(): Boolean {
        return try {
            deleteKey()
            val builder = KeyGenParameterSpec.Builder(
                BiometricBindingPolicy.ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // Every use needs a Class 3 biometric; no device credential.
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            // API 24-29: the default validity (-1) already means "every
            // use, biometric only".
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            generator.init(builder.build())
            generator.generateKey()
            true
        } catch (_: Exception) {
            deleteKey()
            false
        }
    }

    private fun deleteKey() {
        try {
            keyStore().deleteEntry(BiometricBindingPolicy.ALIAS)
        } catch (_: Exception) {
            // Best effort.
        }
    }

    /** A cipher initialised with the key, or the key state that prevents it. */
    private fun initCipher(): Pair<Cipher?, String> {
        val key: SecretKey = try {
            keyStore().getKey(BiometricBindingPolicy.ALIAS, null) as? SecretKey
                ?: return null to BiometricBindingPolicy.keyState(present = false, invalidated = false, failed = false)
        } catch (_: Exception) {
            return null to BiometricBindingPolicy.keyState(present = false, invalidated = false, failed = true)
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher to BiometricBindingPolicy.keyState(present = true, invalidated = false, failed = false)
        } catch (_: KeyPermanentlyInvalidatedException) {
            null to BiometricBindingPolicy.keyState(present = true, invalidated = true, failed = false)
        } catch (_: Exception) {
            null to BiometricBindingPolicy.keyState(present = true, invalidated = false, failed = true)
        }
    }

    private fun checkKey(): String = initCipher().second

    private fun authenticate(
        activity: FragmentActivity,
        reason: String,
        requireConfirmation: Boolean,
        result: MethodChannel.Result,
    ) {
        if (!inProgress.compareAndSet(false, true)) {
            result.error("authInProgress", null, null)
            return
        }
        val replied = AtomicBoolean(false)
        fun reply(block: () -> Unit) {
            if (replied.compareAndSet(false, true)) {
                inProgress.set(false)
                block()
            }
        }
        val (cipher, state) = initCipher()
        if (cipher == null) {
            // A missing key at prompt time is an enrollment change too (D3-b).
            val code = if (state == BiometricBindingPolicy.KEY_ERROR) "deviceError" else BiometricBindingPolicy.CODE_KEY_INVALIDATED
            reply { result.error(code, null, null) }
            return
        }
        val nonce = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(res: BiometricPrompt.AuthenticationResult) {
                val bytes = try {
                    res.cryptoObject?.cipher?.doFinal(nonce)?.size ?: -1
                } catch (_: Exception) {
                    -1
                }
                reply {
                    if (BiometricBindingPolicy.successConfirmed(bytes)) {
                        result.success(true)
                    } else {
                        result.error("deviceError", null, null)
                    }
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                reply { result.error(BiometricBindingPolicy.promptErrorCode(errorCode), null, null) }
            }

            // onAuthenticationFailed: a non-matching biometric; the system
            // prompt stays open and keeps counting (not terminal).
        }
        try {
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(PROMPT_TITLE)
                .setDescription(reason)
                .setNegativeButtonText(NEGATIVE_LABEL)
                .setConfirmationRequired(requireConfirmation)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()
            BiometricPrompt(activity, mainExecutor, callback)
                .authenticate(info, BiometricPrompt.CryptoObject(cipher))
        } catch (_: Exception) {
            reply { result.error("uiUnavailable", null, null) }
        }
    }
}
