package com.smartapplock.app

import android.content.Context
import android.util.Base64
import java.security.SecureRandom
import java.util.Calendar

/**
 * Phase 14 / M1: native copy of the per-app notification privacy modes so
 * the listener can apply them without Dart (same non-secret tier as
 * [ProtectionStateStore]: package names + mode ids only).
 *
 * Absent store = every app OFF. An unreadable or newer store is INVALID and
 * is never treated as OFF ([NotificationPrivacyPolicy.effectiveMode]).
 */
object NotificationPrivacyStore {
    private const val PREFS = "smart_app_lock_notification_privacy"
    private const val KEY_VERSION = "version"
    private const val KEY_MODES = "modes"

    data class Snapshot(val modes: Map<String, NotificationPrivacyPolicy.Mode>, val invalid: Boolean)

    /** Replaces the snapshot. Returns true when it was durably committed. */
    fun configure(context: Context, modes: Map<String, NotificationPrivacyPolicy.Mode>): Boolean =
        try {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putInt(KEY_VERSION, NotificationPrivacyPolicy.STORE_VERSION)
                .putStringSet(KEY_MODES, NotificationPrivacyPolicy.encode(modes))
                .commit()
        } catch (_: Exception) {
            false
        }

    fun read(context: Context): Snapshot = try {
        val preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!preferences.contains(KEY_VERSION)) {
            Snapshot(emptyMap(), invalid = false)
        } else if (preferences.getInt(KEY_VERSION, -1) != NotificationPrivacyPolicy.STORE_VERSION) {
            Snapshot(emptyMap(), invalid = true)
        } else {
            val modes = NotificationPrivacyPolicy.decode(preferences.getStringSet(KEY_MODES, null))
            if (modes == null) Snapshot(emptyMap(), invalid = true) else Snapshot(modes, invalid = false)
        }
    } catch (_: Exception) {
        Snapshot(emptyMap(), invalid = true)
    }

    private const val KEY_SALT = "placeholder_salt"

    /**
     * Phase 14 / M2: random per-install salt for the opaque placeholder tags
     * ([NotificationPrivacyEngine.placeholderTag]). Not a secret credential;
     * it only keeps other notification listeners from mapping a placeholder
     * tag back to an app.
     */
    @Synchronized
    fun placeholderSalt(context: Context): ByteArray {
        val preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        preferences.getString(KEY_SALT, null)?.let { stored ->
            try {
                val bytes = Base64.decode(stored, Base64.NO_WRAP)
                if (bytes.size == 16) return bytes
            } catch (_: Exception) {
                // Replaced below (tags are not persisted anywhere else).
            }
        }
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        preferences.edit().putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP)).commit()
        return salt
    }

    fun state(context: Context, nowWallMs: Long = System.currentTimeMillis()): NotificationPrivacyPolicy.State {
        val snapshot = read(context)
        val protectedPackages = ProtectionStateStore.protectedPackages(context)
        // M3: rule/profile floors at this instant (same clock as the lock).
        val rules = ProtectionStateStore.smartRules(context)
        val calendar = Calendar.getInstance().apply { timeInMillis = nowWallMs }
        return NotificationPrivacyPolicy.State(
            ownPackage = context.packageName,
            protectionEnabled = ProtectionStateStore.isEnabled(context),
            protectedPackages = protectedPackages,
            modes = snapshot.modes,
            storeInvalid = snapshot.invalid,
            ruleFloors = NotificationPrivacyPolicy.ruleFloors(
                rules.rules,
                rules.damaged,
                protectedPackages,
                SmartRulePolicy.isoDayFromCalendar(calendar.get(Calendar.DAY_OF_WEEK)),
                calendar.get(Calendar.HOUR_OF_DAY) * 60 + calendar.get(Calendar.MINUTE),
            ),
            ruleTargeted = NotificationPrivacyPolicy.ruleTargeted(rules.rules, rules.damaged, protectedPackages),
        )
    }

    /** M3: delay until the next rule-window boundary (see the policy). */
    fun nextRuleCheckDelayMs(context: Context, nowWallMs: Long = System.currentTimeMillis()): Long {
        val calendar = Calendar.getInstance().apply { timeInMillis = nowWallMs }
        return NotificationPrivacyPolicy.nextRuleCheckDelayMs(
            ProtectionStateStore.smartRules(context).rules,
            calendar.get(Calendar.HOUR_OF_DAY) * 60 + calendar.get(Calendar.MINUTE),
            (calendar.get(Calendar.SECOND) * 1000 + calendar.get(Calendar.MILLISECOND)).toLong(),
        )
    }
}
