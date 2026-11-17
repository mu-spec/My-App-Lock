package com.smartapplock.app

import com.smartapplock.app.NotificationPrivacyPolicy.Decision
import com.smartapplock.app.NotificationPrivacyPolicy.Mode
import java.security.MessageDigest

/**
 * Phase 14 / M2: privacy modes (pure, JVM-testable; Android glue in
 * [SalNotificationListenerService] / [NotificationPlaceholders]).
 *
 * For an eligible notification (protected app, same user, mode not Off,
 * removable) the original is cancelled through the listener and, once Android
 * confirms the cancellation, ONE neutral placeholder per app is shown:
 * - Hide content: title = the app's label (from PackageManager, never from
 *   the notification) + "New notification"; lock screen shows only
 *   "New notification".
 * - Maximum: "New notification" only (Android adds "Smart App Lock" as the
 *   header); silent (min importance) and secret on the lock screen.
 *
 * Only metadata is ever read: key, package, flags, user, and the tag of OUR
 * OWN notifications. Title, text, extras, people, images, actions and intents
 * of other apps are never read, copied, stored or logged.
 *
 * Android limits (documented, not hidden): Android shows/alerts a notification
 * BEFORE any listener sees it, so a heads-up, lock-screen display, sound,
 * vibration or wearable bridge may already have happened; ongoing,
 * no-clear and foreground-service notifications cannot be removed by a
 * listener and are left untouched (an original Android refuses to cancel is
 * never confirmed, so no placeholder is added next to it).
 */
class NotificationPrivacyEngine(private val port: Port) {

    /** Metadata of one posted/removed notification. [tag] is set only for
     * Smart App Lock's own notifications. */
    data class Posted(
        val key: String,
        val packageName: String,
        val flags: Int,
        val sameUser: Boolean,
        val tag: String? = null,
    )

    /** Why Android removed a notification (API 26+ reports a reason). */
    enum class RemovalCause { LISTENER, OTHER, UNKNOWN }

    enum class LockScreen {
        /** Full placeholder only when the user allows private content on the
         * lock screen; otherwise [Placeholder.publicTitle]. */
        PRIVATE,
        SECRET,
    }

    enum class Importance { LOW, MIN }

    /** Everything the glue may put in a placeholder. Nothing else is added. */
    data class Placeholder(
        val tag: String,
        val sourcePackage: String,
        val mode: Mode,
        val channelId: String,
        val title: String,
        val text: String?,
        val publicTitle: String?,
        val lockScreen: LockScreen,
        val importance: Importance,
    )

    interface Port {
        fun state(): NotificationPrivacyPolicy.State
        fun placeholderTag(packageName: String): String
        fun appLabel(packageName: String): String?

        /** POST_NOTIFICATIONS granted, app notifications and [mode]'s
         * channel enabled. */
        fun canPostPlaceholders(mode: Mode): Boolean
        fun cancelSource(key: String): Boolean
        fun postPlaceholder(placeholder: Placeholder): Boolean
    }

    private var connected = false

    /** Originals we asked Android to cancel: key -> package (bounded). */
    private val pending = LinkedHashMap<String, String>()

    /** Placeholders believed visible: package -> rendered mode. */
    private val shown = HashMap<String, Mode>()

    val isConnected: Boolean get() = connected
    val pendingCount: Int @Synchronized get() = pending.size

    @Synchronized
    fun shownModes(): Map<String, Mode> = HashMap(shown)

    /** Listener (re)connected (also after process death / reboot). The
     * in-memory state is rebuilt from what Android reports as active. */
    @Synchronized
    fun onConnected(active: List<Posted>) {
        connected = true
        pending.clear()
        shown.clear()
        val state = port.state()
        val byTag = tagsFor(state)
        for (n in active) {
            if (n.packageName != state.ownPackage) continue
            val pkg = byTag[n.tag ?: continue] ?: continue
            val mode = NotificationPrivacyPolicy.effectiveMode(state, pkg)
            // Re-render in place (same tag/id: an update, never a duplicate).
            if (mode != Mode.OFF) show(pkg, mode, force = true)
        }
        sweep(state, active)
    }

    @Synchronized
    fun onDisconnected() {
        connected = false
        pending.clear()
        shown.clear()
    }

    @Synchronized
    fun onPosted(n: Posted) {
        if (!connected) return
        val state = port.state()
        // Recursion guard: Smart App Lock's own notifications (placeholders,
        // the protection service notification) are never processed.
        if (n.packageName == state.ownPackage) return
        handle(state, n)
    }

    @Synchronized
    fun onRemoved(n: Posted, cause: RemovalCause) {
        if (!connected) return
        val state = port.state()
        if (n.packageName == state.ownPackage) {
            // A placeholder was opened or dismissed: the next one may show.
            tagsFor(state)[n.tag]?.let { shown.remove(it) }
            return
        }
        val pkg = pending.remove(n.key) ?: return
        if (pkg != n.packageName || cause == RemovalCause.OTHER) return
        val mode = NotificationPrivacyPolicy.effectiveMode(state, pkg)
        if (mode != Mode.OFF) show(pkg, mode, force = false)
    }

    /** The per-app modes or the protected set changed. Placeholders are only
     * ever re-rendered STRICTER in place; active originals are re-checked. */
    @Synchronized
    fun onConfigurationChanged(active: List<Posted>) {
        if (!connected) return
        val state = port.state()
        for ((pkg, rendered) in shown.toMap()) {
            val mode = NotificationPrivacyPolicy.effectiveMode(state, pkg)
            if (mode.rank > rendered.rank) show(pkg, mode, force = false)
        }
        sweep(state, active)
    }

    private fun sweep(state: NotificationPrivacyPolicy.State, active: List<Posted>) {
        for (n in active) if (n.packageName != state.ownPackage) handle(state, n)
    }

    private fun handle(state: NotificationPrivacyPolicy.State, n: Posted) {
        when (classify(state, n)) {
            Decision.HIDE_CONTENT, Decision.MAXIMUM -> {
                pending.remove(n.key)
                pending[n.key] = n.packageName
                while (pending.size > MAX_PENDING) pending.remove(pending.keys.first())
                if (!port.cancelSource(n.key)) pending.remove(n.key)
            }
            else -> Unit
        }
    }

    private fun show(pkg: String, mode: Mode, force: Boolean) {
        val current = shown[pkg]
        // Duplicate guard: one placeholder per app, never weakened in place.
        if (!force && current != null && current.rank >= mode.rank) return
        if (!port.canPostPlaceholders(mode)) return
        val placeholder = placeholderFor(pkg, mode, port.placeholderTag(pkg), port.appLabel(pkg))
        if (port.postPlaceholder(placeholder)) shown[pkg] = mode
    }

    private fun tagsFor(state: NotificationPrivacyPolicy.State): Map<String, String> =
        (state.protectedPackages + state.modes.keys).associateBy { port.placeholderTag(it) }

    companion object {
        const val MAX_PENDING = 500
        const val NEW_NOTIFICATION = "New notification"
        const val CHANNEL_HIDDEN = "smart_app_lock_np_hidden"
        const val CHANNEL_MAXIMUM = "smart_app_lock_np_maximum"
        const val TAG_PREFIX = "salnp_"
        private const val MAX_LABEL = 60

        // android.app.Notification flag values (stable public API constants).
        const val FLAG_ONGOING_EVENT = 0x00000002
        const val FLAG_NO_CLEAR = 0x00000020
        const val FLAG_FOREGROUND_SERVICE = 0x00000040

        // NotificationListenerService.REASON_LISTENER_CANCEL(_ALL), API 26.
        const val REASON_LISTENER_CANCEL = 10
        const val REASON_LISTENER_CANCEL_ALL = 11

        fun isOngoing(flags: Int): Boolean = flags and FLAG_ONGOING_EVENT != 0

        /** A listener may remove it. Anything else Android refuses to cancel
         * is never confirmed (see [onRemoved]), so no placeholder appears. */
        fun isRemovable(flags: Int): Boolean =
            flags and (FLAG_ONGOING_EVENT or FLAG_NO_CLEAR or FLAG_FOREGROUND_SERVICE) == 0

        fun classify(state: NotificationPrivacyPolicy.State, n: Posted): Decision = when {
            n.packageName == state.ownPackage -> Decision.IGNORE_OWN_APP
            // Another user / work profile: a different app instance, never touched.
            !n.sameUser -> Decision.IGNORE_NOT_PROTECTED
            else -> NotificationPrivacyPolicy.decide(
                state,
                n.packageName,
                ongoing = isOngoing(n.flags),
                clearable = isRemovable(n.flags),
            )
        }

        fun removalCause(sdk: Int, reason: Int?): RemovalCause = when {
            sdk < 26 || reason == null -> RemovalCause.UNKNOWN
            reason == REASON_LISTENER_CANCEL || reason == REASON_LISTENER_CANCEL_ALL -> RemovalCause.LISTENER
            else -> RemovalCause.OTHER
        }

        fun placeholderFor(pkg: String, mode: Mode, tag: String, label: String?): Placeholder {
            val name = label?.trim()?.takeIf { it.isNotEmpty() }?.take(MAX_LABEL)
            return when (mode) {
                Mode.HIDE_CONTENT -> Placeholder(
                    tag = tag,
                    sourcePackage = pkg,
                    mode = mode,
                    channelId = CHANNEL_HIDDEN,
                    title = name ?: NEW_NOTIFICATION,
                    text = if (name != null) NEW_NOTIFICATION else null,
                    publicTitle = NEW_NOTIFICATION,
                    lockScreen = LockScreen.PRIVATE,
                    importance = Importance.LOW,
                )
                Mode.MAXIMUM -> Placeholder(
                    tag = tag,
                    sourcePackage = pkg,
                    mode = mode,
                    channelId = CHANNEL_MAXIMUM,
                    title = NEW_NOTIFICATION,
                    text = null,
                    publicTitle = null,
                    lockScreen = LockScreen.SECRET,
                    importance = Importance.MIN,
                )
                Mode.OFF -> throw IllegalArgumentException("no placeholder for OFF")
            }
        }

        /** Opaque per-install tag: other listeners can see our notifications,
         * so the tag must not reveal which app it stands for. */
        fun placeholderTag(salt: ByteArray, pkg: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(salt)
            digest.update(0)
            digest.update(pkg.toByteArray(Charsets.UTF_8))
            return TAG_PREFIX + digest.digest().take(16).joinToString("") { "%02x".format(it) }
        }

        /** A placeholder tap may only open the protected source app itself
         * (its launcher activity), never Smart App Lock: the existing
         * foreground lock then challenges it like any notification entry. */
        fun tapTargetAllowed(ownPackage: String, sourcePackage: String, launchPackage: String?): Boolean =
            launchPackage != null && launchPackage == sourcePackage && sourcePackage != ownPackage &&
                NotificationPrivacyPolicy.isValidPackage(sourcePackage)
    }
}
