package com.smartapplock.app

/**
 * Phase 13 / M3 (N-1): decides whether native diagnostics may be emitted.
 *
 * Pure JVM logic (no Android types) so it is unit-testable. Diagnostics are
 * allowed only when the installed application is debuggable, i.e. a debug
 * build. Release and profile builds are not debuggable, so nothing is
 * logged there. Unknown flags (null) or an invalid mask fail closed: no
 * logging. Enforcement never consults this policy.
 */
internal object ReleaseLogPolicy {
    /**
     * @param applicationFlags `ApplicationInfo.flags` of the running app,
     *   or null when it could not be read.
     * @param debuggableMask `ApplicationInfo.FLAG_DEBUGGABLE`, passed in by
     *   [DiagLog] so the constant comes from the real Android API.
     */
    fun allows(applicationFlags: Int?, debuggableMask: Int): Boolean {
        if (applicationFlags == null) return false
        if (debuggableMask == 0) return false
        return (applicationFlags and debuggableMask) == debuggableMask
    }
}
