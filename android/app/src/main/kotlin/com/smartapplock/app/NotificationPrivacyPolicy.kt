package com.smartapplock.app

/**
 * Phase 14 / M1: notification privacy policy, pure (JVM-testable).
 *
 * Mechanism (owner decision): Android's NotificationListenerService, a
 * user-granted special access. Without it, the user is linked to Android's
 * own per-app notification settings instead.
 *
 * Privacy rules for every consumer of this policy:
 * - Only the posting package and the notification's ongoing/clearable flags
 *   are ever inspected. Title, text, extras, people and actions are never
 *   read, stored, logged or sent anywhere.
 * - Only PROTECTED apps (while protection is enabled) are eligible. A stored
 *   mode for an app that is no longer protected is ignored.
 * - A stored snapshot that cannot be read is never treated as "off": every
 *   protected app is handled with the strictest mode until Smart App Lock
 *   rewrites a valid snapshot (fail closed toward privacy).
 */
object NotificationPrivacyPolicy {
    /** Per-app mode. [rank] orders strictness (higher = more private). */
    enum class Mode(val id: String, val rank: Int) {
        OFF("off", 0),
        HIDE_CONTENT("hide_content", 1),
        MAXIMUM("maximum", 2);

        companion object {
            fun fromId(id: String?): Mode? = values().firstOrNull { it.id == id }
        }
    }

    /** What to do with one posted notification. */
    enum class Decision {
        IGNORE_OWN_APP,
        IGNORE_NOT_PROTECTED,
        IGNORE_PRIVACY_OFF,

        /** Ongoing / non-clearable (e.g. foreground service): Android does
         * not let a listener remove it. Reported, never hidden. */
        CANNOT_HIDE,
        HIDE_CONTENT,
        MAXIMUM,
    }

    const val STORE_VERSION = 1
    const val MAX_ENTRIES = 500
    private const val SEP = '|'
    private val PACKAGE = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")

    fun isValidPackage(packageName: String?): Boolean =
        packageName != null && packageName.length <= 255 && PACKAGE.matches(packageName)

    /**
     * Validates a snapshot sent by Dart (`package -> mode id`). OFF entries
     * are dropped. Returns null (the whole snapshot is refused, nothing is
     * stored) when any package or mode is invalid or there are too many.
     */
    fun normalize(raw: Map<*, *>?): Map<String, Mode>? {
        if (raw == null || raw.size > MAX_ENTRIES) return null
        val out = HashMap<String, Mode>()
        for ((k, v) in raw) {
            val pkg = k as? String ?: return null
            if (!isValidPackage(pkg)) return null
            val mode = Mode.fromId(v as? String) ?: return null
            if (mode != Mode.OFF) out[pkg] = mode
        }
        return out
    }

    fun encode(modes: Map<String, Mode>): Set<String> =
        modes.filterValues { it != Mode.OFF }
            .map { (pkg, mode) -> "$pkg$SEP${mode.id}" }
            .toSet()

    /** Null when any entry is invalid (the caller treats that as invalid). */
    fun decode(entries: Set<String>?): Map<String, Mode>? {
        if (entries == null || entries.size > MAX_ENTRIES) return null
        val out = HashMap<String, Mode>()
        for (entry in entries) {
            val i = entry.indexOf(SEP)
            if (i <= 0 || entry.indexOf(SEP, i + 1) >= 0) return null
            val pkg = entry.substring(0, i)
            val mode = Mode.fromId(entry.substring(i + 1)) ?: return null
            if (!isValidPackage(pkg) || mode == Mode.OFF || out.containsKey(pkg)) return null
            out[pkg] = mode
        }
        return out
    }

    /** Native view of the configuration (protected set + stored modes). */
    data class State(
        val ownPackage: String,
        val protectionEnabled: Boolean,
        val protectedPackages: Set<String>,
        val modes: Map<String, Mode>,
        val storeInvalid: Boolean,
    )

    /** The mode in force for [packageName] (OFF when not eligible). */
    fun effectiveMode(state: State, packageName: String): Mode {
        if (packageName == state.ownPackage) return Mode.OFF
        if (!state.protectionEnabled || packageName !in state.protectedPackages) return Mode.OFF
        if (state.storeInvalid) return Mode.MAXIMUM
        return state.modes[packageName] ?: Mode.OFF
    }

    fun decide(state: State, packageName: String, ongoing: Boolean, clearable: Boolean): Decision {
        if (packageName == state.ownPackage) return Decision.IGNORE_OWN_APP
        if (!state.protectionEnabled || packageName !in state.protectedPackages) {
            return Decision.IGNORE_NOT_PROTECTED
        }
        return when (effectiveMode(state, packageName)) {
            Mode.OFF -> Decision.IGNORE_PRIVACY_OFF
            Mode.HIDE_CONTENT -> if (ongoing || !clearable) Decision.CANNOT_HIDE else Decision.HIDE_CONTENT
            Mode.MAXIMUM -> if (ongoing || !clearable) Decision.CANNOT_HIDE else Decision.MAXIMUM
        }
    }

    /**
     * Data minimization: the listener should stay bound only while at least
     * one protected app has privacy on (or the snapshot is unreadable).
     */
    fun listenerWanted(state: State): Boolean =
        state.protectionEnabled &&
            (state.storeInvalid || state.modes.keys.any { it in state.protectedPackages })

    // -- Settings links (allowlist; opening a screen grants nothing) --------

    const val ACTION_LISTENER_SETTINGS = "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"
    const val ACTION_LISTENER_DETAIL_SETTINGS =
        "android.settings.NOTIFICATION_LISTENER_DETAIL_SETTINGS"
    const val EXTRA_LISTENER_COMPONENT =
        "android.provider.extra.NOTIFICATION_LISTENER_COMPONENT_NAME"

    /** Notification-access screens to try, in order, on API [sdk]. */
    fun accessSettingsActions(sdk: Int): List<String> =
        if (sdk >= 30) {
            listOf(ACTION_LISTENER_DETAIL_SETTINGS, ACTION_LISTENER_SETTINGS)
        } else {
            listOf(ACTION_LISTENER_SETTINGS)
        }

    /** Android's own notification settings may be opened only for a valid,
     * currently protected package (the fallback when access is not granted). */
    fun mayOpenAppNotificationSettings(packageName: String?, protectedPackages: Set<String>): Boolean =
        isValidPackage(packageName) && packageName in protectedPackages

    /**
     * Pre-API-27 access check: Settings.Secure `enabled_notification_listeners`
     * is a ':'-separated list of flattened component names.
     */
    fun listenerEnabledIn(flat: String?, ownPackage: String, listenerClass: String): Boolean {
        if (flat.isNullOrEmpty()) return false
        val full = "$ownPackage/$listenerClass"
        val short = if (listenerClass.startsWith("$ownPackage.")) {
            "$ownPackage/${listenerClass.removePrefix(ownPackage)}"
        } else {
            null
        }
        return flat.split(':').any { it == full || (short != null && it == short) }
    }
}
