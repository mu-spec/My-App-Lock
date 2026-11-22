package com.smartapplock.app

import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Phase 18 / M1F (F18-2): `smart_app_lock/monotonic_clock`.
 * Method `read` → `{elapsedMs, bootCount}` ([MonotonicClock.reading]).
 * Any failure is reported as an error code only; the Dart side then applies
 * the wall-clock fallback (owner decision D2-a). Read-only; no logging.
 */
object MonotonicClockChannel {
    const val CHANNEL = "smart_app_lock/monotonic_clock"

    fun register(engine: FlutterEngine, context: Context) {
        val app = context.applicationContext
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "read" -> {
                    val boot: Int? = try {
                        Settings.Global.getInt(app.contentResolver, Settings.Global.BOOT_COUNT, MonotonicClock.UNKNOWN_BOOT_COUNT)
                    } catch (_: Exception) {
                        null
                    }
                    val reading = MonotonicClock.reading(SystemClock.elapsedRealtime(), boot)
                    if (reading == null) {
                        result.error("unavailable", null, null)
                    } else {
                        result.success(reading)
                    }
                }
                else -> result.notImplemented()
            }
        }
    }
}
