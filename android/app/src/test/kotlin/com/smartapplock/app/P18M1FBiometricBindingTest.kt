package com.smartapplock.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 18 / M1F (F18-3, Option B). SIMULATED (JVM): the pure decisions of
 * the Keystore-bound biometric channel. Keystore invalidation on a new
 * enrollment and the real prompt are DEVICE PENDING.
 */
class P18M1FBiometricBindingTest {
    private val cancellation = setOf("userCanceled", "systemCanceled", "timeout")

    @Test fun negativeButtonAndUserCancelAreCancellationsNotCountedErrors() {
        assertEquals("userCanceled", BiometricBindingPolicy.promptErrorCode(BiometricBindingPolicy.ERROR_NEGATIVE_BUTTON))
        assertEquals("userCanceled", BiometricBindingPolicy.promptErrorCode(BiometricBindingPolicy.ERROR_USER_CANCELED))
        assertEquals("systemCanceled", BiometricBindingPolicy.promptErrorCode(BiometricBindingPolicy.ERROR_CANCELED))
        assertEquals("timeout", BiometricBindingPolicy.promptErrorCode(BiometricBindingPolicy.ERROR_TIMEOUT))
    }

    @Test fun availabilityErrorsMapToStableCodesAndUnknownIsCounted() {
        val p = BiometricBindingPolicy
        assertEquals("temporaryLockout", p.promptErrorCode(p.ERROR_LOCKOUT))
        assertEquals("biometricLockout", p.promptErrorCode(p.ERROR_LOCKOUT_PERMANENT))
        assertEquals("noBiometricsEnrolled", p.promptErrorCode(p.ERROR_NO_BIOMETRICS))
        assertEquals("noBiometricHardware", p.promptErrorCode(p.ERROR_HW_NOT_PRESENT))
        assertEquals("biometricHardwareTemporarilyUnavailable", p.promptErrorCode(p.ERROR_HW_UNAVAILABLE))
        assertEquals("noCredentialsSet", p.promptErrorCode(p.ERROR_NO_DEVICE_CREDENTIAL))
        // Unrecognized / vendor errors are never cancellations (they count).
        for (code in listOf(p.ERROR_UNABLE_TO_PROCESS, p.ERROR_NO_SPACE, p.ERROR_VENDOR, 99, -1)) {
            assertEquals("deviceError", p.promptErrorCode(code))
            assertFalse(p.promptErrorCode(code) in cancellation)
        }
    }

    @Test fun keyStatePriorities() {
        val p = BiometricBindingPolicy
        assertEquals("valid", p.keyState(present = true, invalidated = false, failed = false))
        assertEquals("invalidated", p.keyState(present = true, invalidated = true, failed = false))
        assertEquals("missing", p.keyState(present = false, invalidated = false, failed = false))
        // A keystore failure is transient: never reported as invalid/missing.
        assertEquals("error", p.keyState(present = false, invalidated = false, failed = true))
        assertEquals("error", p.keyState(present = true, invalidated = true, failed = true))
    }

    @Test fun successNeedsCipherOutput() {
        assertTrue(BiometricBindingPolicy.successConfirmed(32))
        assertFalse(BiometricBindingPolicy.successConfirmed(0))
        assertFalse(BiometricBindingPolicy.successConfirmed(-1))
    }

    @Test fun codesAndAliasMatchTheDartContract() {
        assertEquals("keyInvalidated", BiometricBindingPolicy.CODE_KEY_INVALIDATED)
        assertEquals("sal_bio_binding_v1", BiometricBindingPolicy.ALIAS)
    }
}
