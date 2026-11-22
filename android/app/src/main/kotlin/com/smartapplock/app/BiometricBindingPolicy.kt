package com.smartapplock.app

/**
 * Phase 18 / M1F (F18-3, owner-approved Option B): pure decisions for
 * [BiometricBindingChannel] (JVM-testable, no Android types).
 *
 * The ERROR_* values are androidx.biometric 1.1.0 `BiometricPrompt` error
 * codes; `compile_native_p18m1f.sh` checks each one against the real
 * library with javap. Codes returned to Dart are the stable, non-localized
 * codes of `BiometricAuthException` (platform text is never forwarded).
 */
object BiometricBindingPolicy {
    /** Keystore alias of the binding key. */
    const val ALIAS = "sal_bio_binding_v1"

    const val KEY_VALID = "valid"
    const val KEY_INVALIDATED = "invalidated"
    const val KEY_MISSING = "missing"
    const val KEY_ERROR = "error"

    /** Same string as Dart `BiometricAuthException.keyInvalidatedCode`. */
    const val CODE_KEY_INVALIDATED = "keyInvalidated"

    const val ERROR_HW_UNAVAILABLE = 1
    const val ERROR_UNABLE_TO_PROCESS = 2
    const val ERROR_TIMEOUT = 3
    const val ERROR_NO_SPACE = 4
    const val ERROR_CANCELED = 5
    const val ERROR_LOCKOUT = 7
    const val ERROR_VENDOR = 8
    const val ERROR_LOCKOUT_PERMANENT = 9
    const val ERROR_USER_CANCELED = 10
    const val ERROR_NO_BIOMETRICS = 11
    const val ERROR_HW_NOT_PRESENT = 12
    const val ERROR_NEGATIVE_BUTTON = 13
    const val ERROR_NO_DEVICE_CREDENTIAL = 14
    const val ERROR_SECURITY_UPDATE_REQUIRED = 15

    /**
     * BiometricPrompt error → Dart code. The negative button ("use the app
     * PIN or pattern") is a cancellation, never a counted rejection.
     * Unrecognized codes map to `deviceError` (counted by the manager, so a
     * failing prompt can never dodge the lockout).
     */
    fun promptErrorCode(errorCode: Int): String = when (errorCode) {
        ERROR_USER_CANCELED, ERROR_NEGATIVE_BUTTON -> "userCanceled"
        ERROR_CANCELED -> "systemCanceled"
        ERROR_TIMEOUT -> "timeout"
        ERROR_LOCKOUT -> "temporaryLockout"
        ERROR_LOCKOUT_PERMANENT -> "biometricLockout"
        ERROR_NO_BIOMETRICS -> "noBiometricsEnrolled"
        ERROR_HW_NOT_PRESENT, ERROR_SECURITY_UPDATE_REQUIRED -> "noBiometricHardware"
        ERROR_HW_UNAVAILABLE -> "biometricHardwareTemporarilyUnavailable"
        ERROR_NO_DEVICE_CREDENTIAL -> "noCredentialsSet"
        else -> "deviceError"
    }

    /**
     * Key state from the keystore probe: [present] = an entry exists under
     * [ALIAS]; [invalidated] = `Cipher.init` threw
     * KeyPermanentlyInvalidatedException; [failed] = any other keystore
     * error (transient: nothing is changed by the caller).
     */
    fun keyState(present: Boolean, invalidated: Boolean, failed: Boolean): String =
        when {
            failed -> KEY_ERROR
            !present -> KEY_MISSING
            invalidated -> KEY_INVALIDATED
            else -> KEY_VALID
        }

    /**
     * Success is reported only when the authenticated cipher produced
     * output (`doFinal` returned bytes): a callback without a working
     * CryptoObject never unlocks. [bytes] is -1 when no output exists.
     */
    fun successConfirmed(bytes: Int): Boolean = bytes > 0
}
