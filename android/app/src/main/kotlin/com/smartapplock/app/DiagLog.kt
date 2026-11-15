package com.smartapplock.app

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log

/**
 * Phase 13 / M3 (N-1): the ONLY native logging entry point.
 *
 * Diagnostics may contain package names, pending-challenge details and
 * security-state identifiers, so they are emitted only by debuggable
 * builds (see [ReleaseLogPolicy]). In a release build every call returns
 * before the message lambda runs: nothing reaches logcat, and no message
 * text is even built. Message lambdas must be side-effect free; app
 * behaviour never depends on whether a diagnostic is emitted.
 *
 * `android.util.Log` must not be used anywhere else in native sources
 * (enforced by test/regression/p13_m3_release_logging_test.dart).
 */
internal object DiagLog {
    fun enabled(context: Context): Boolean = try {
        ReleaseLogPolicy.allows(
            context.applicationInfo?.flags,
            ApplicationInfo.FLAG_DEBUGGABLE,
        )
    } catch (_: Exception) {
        false
    }

    fun d(context: Context, tag: String, message: () -> String) {
        if (!enabled(context)) return
        Log.d(tag, message())
    }

    fun w(context: Context, tag: String, error: Throwable? = null, message: () -> String) {
        if (!enabled(context)) return
        if (error == null) {
            Log.w(tag, message())
        } else {
            Log.w(tag, message(), error)
        }
    }
}
