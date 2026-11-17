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

    /**
     * Native view of the configuration (protected set + stored modes).
     *
     * Phase 14 / M3 (owner decision "linked to levels"): [ruleFloors] holds,
     * for protected packages, the floor implied NOW by the persisted Smart
     * Rules transport, which already carries the active profile's overlay
     * and the "Apply profile" rules (Phase 11): a rule/profile raising an app
     * to Critical -> MAXIMUM, Sensitive -> HIDE_CONTENT. The saved baseline
     * level alone implies nothing. [ruleTargeted] = protected packages any
     * rule targets at any time (keeps the listener bound across windows).
     */
    data class State(
        val ownPackage: String,
        val protectionEnabled: Boolean,
        val protectedPackages: Set<String>,
        val modes: Map<String, Mode>,
        val storeInvalid: Boolean,
        val ruleFloors: Map<String, Mode> = emptyMap(),
        val ruleTargeted: Set<String> = emptySet(),
    )

    fun stricter(a: Mode, b: Mode): Mode = if (a.rank >= b.rank) a else b

    /** M3: the notification floor of an enforced rule/profile level. */
    fun floorFor(level: SecurityLevel?): Mode = when (level) {
        SecurityLevel.CRITICAL -> Mode.MAXIMUM
        SecurityLevel.SENSITIVE -> Mode.HIDE_CONTENT
        SecurityLevel.STANDARD, null -> Mode.OFF
    }

    /**
     * M3: rule/profile floors of the protected packages at ([isoDay],
     * [minute]). A damaged rule store fails closed exactly like the lock
     * (Critical -> every protected app MAXIMUM).
     */
    fun ruleFloors(
        rules: Collection<SmartRuleSpec>,
        damaged: Boolean,
        protectedPackages: Set<String>,
        isoDay: Int,
        minute: Int,
    ): Map<String, Mode> {
        if (damaged) return protectedPackages.associateWith { Mode.MAXIMUM }
        if (rules.isEmpty()) return emptyMap()
        val out = HashMap<String, Mode>()
        for (pkg in protectedPackages) {
            val floor = floorFor(SmartRulePolicy.ruleLevel(rules, pkg, isoDay, minute))
            if (floor != Mode.OFF) out[pkg] = floor
        }
        return out
    }

    fun ruleTargeted(rules: Collection<SmartRuleSpec>, damaged: Boolean, protectedPackages: Set<String>): Set<String> =
        if (damaged) protectedPackages else protectedPackages.intersect(rules.flatMap { it.targets }.toSet())

    /**
     * M3: delay until the next instant a rule floor can change (a window
     * start/end, or midnight for day changes), +1 s, capped at 15 min so a
     * clock or time-zone change is picked up.
     */
    fun nextRuleCheckDelayMs(rules: Collection<SmartRuleSpec>, minuteOfDay: Int, msIntoMinute: Long): Long {
        val boundaries = sortedSetOf(SmartRulePolicy.MINUTES_PER_DAY)
        for (rule in rules) if (!rule.allDay) {
            boundaries += rule.start
            boundaries += rule.end
        }
        val next = boundaries.first { it > minuteOfDay }
        val delay = (next - minuteOfDay) * 60_000L - msIntoMinute + 1_000L
        return delay.coerceIn(1_000L, MAX_RULE_CHECK_DELAY_MS)
    }

    const val MAX_RULE_CHECK_DELAY_MS = 15 * 60_000L

    /** The mode in force for [packageName] (OFF when not eligible): the
     * stricter of the owner's per-app mode and the M3 rule/profile floor;
     * never weaker than the per-app mode. */
    fun effectiveMode(state: State, packageName: String): Mode {
        if (packageName == state.ownPackage) return Mode.OFF
        if (!state.protectionEnabled || packageName !in state.protectedPackages) return Mode.OFF
        if (state.storeInvalid) return Mode.MAXIMUM
        return stricter(state.modes[packageName] ?: Mode.OFF, state.ruleFloors[packageName] ?: Mode.OFF)
    }

    /** M3: protected packages whose floor is stricter than their per-app
     * mode right now (shown in the settings screen; package -> mode). */
    fun raisedNow(state: State): Map<String, Mode> {
        if (!state.protectionEnabled || state.storeInvalid) return emptyMap()
        return state.ruleFloors.filter { (pkg, floor) ->
            pkg != state.ownPackage && pkg in state.protectedPackages &&
                floor.rank > (state.modes[pkg] ?: Mode.OFF).rank
        }
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
     * one protected app has privacy on, a rule/profile targets one (M3), or
     * the snapshot is unreadable.
     */
    fun listenerWanted(state: State): Boolean =
        state.protectionEnabled &&
            (
                state.storeInvalid ||
                    state.modes.keys.any { it in state.protectedPackages } ||
                    state.ruleTargeted.any { it in state.protectedPackages }
                )

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
