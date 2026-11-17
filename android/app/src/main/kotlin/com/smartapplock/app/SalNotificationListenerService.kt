package com.smartapplock.app

import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import java.lang.ref.WeakReference

/**
 * Phase 14: notification privacy (user-granted Notification access).
 *
 * M1: tracks the binding and unbinds itself when no protected app has privacy
 * on (data minimization).
 * M2: hands notification METADATA to [NotificationPrivacyEngine], which
 * removes eligible originals and shows neutral placeholders.
 * M3: profile/rule floors (see [NotificationPrivacyPolicy.State]). A profile
 * switch arrives through `configureProtection` ([refreshBinding]); a rule
 * window starting/ending is re-checked by a main-looper timer set to the next
 * boundary (no alarm, no wake lock; capped at 15 min).
 *
 * Only `key`, `packageName`, `notification.flags`, `user` and (for Smart App
 * Lock's own notifications only) `tag` are read. Nothing about any
 * notification is stored or logged here.
 */
class SalNotificationListenerService : NotificationListenerService() {
    private val engine by lazy { NotificationPrivacyEngine(Port(this)) }
    private val handler = Handler(Looper.getMainLooper())
    private val ruleCheck = Runnable { reevaluate() }

    /** Re-checks active notifications and placeholders, then re-arms the
     * rule-boundary timer while any rule/profile targets a protected app. */
    private fun reevaluate() {
        guard { engine.onConfigurationChanged(activeMetadata()) }
        scheduleRuleCheck()
    }

    private fun scheduleRuleCheck() {
        handler.removeCallbacks(ruleCheck)
        guard {
            if (connected && NotificationPrivacyStore.state(this).ruleTargeted.isNotEmpty()) {
                handler.postDelayed(ruleCheck, NotificationPrivacyStore.nextRuleCheckDelayMs(this))
            }
        }
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        instance = WeakReference(this)
        connected = true
        if (!NotificationPrivacyPolicy.listenerWanted(NotificationPrivacyStore.state(this))) {
            try {
                requestUnbind()
            } catch (_: Exception) {
                // Stays bound; the engine still decides per notification.
            }
        }
        guard { engine.onConnected(activeMetadata()) }
        scheduleRuleCheck()
    }

    override fun onListenerDisconnected() {
        connected = false
        instance = null
        handler.removeCallbacks(ruleCheck)
        guard { engine.onDisconnected() }
        super.onListenerDisconnected()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null) return
        guard { engine.onPosted(metadata(sbn)) }
    }

    /** API 24-25 (no removal reason). On API 26+ the 3-argument overload
     * below is called instead (it does not call super). */
    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        if (sbn == null) return
        guard { engine.onRemoved(metadata(sbn), NotificationPrivacyEngine.removalCause(Build.VERSION.SDK_INT, null)) }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?, rankingMap: RankingMap?, reason: Int) {
        if (sbn == null) return
        guard { engine.onRemoved(metadata(sbn), NotificationPrivacyEngine.removalCause(Build.VERSION.SDK_INT, reason)) }
    }

    private fun metadata(sbn: StatusBarNotification): NotificationPrivacyEngine.Posted {
        val own = sbn.packageName == packageName
        return NotificationPrivacyEngine.Posted(
            key = sbn.key,
            packageName = sbn.packageName,
            flags = sbn.notification?.flags ?: 0,
            sameUser = sbn.user == Process.myUserHandle(),
            tag = if (own) sbn.tag else null,
        )
    }

    private fun activeMetadata(): List<NotificationPrivacyEngine.Posted> = try {
        activeNotifications?.map(::metadata) ?: emptyList()
    } catch (_: Exception) {
        emptyList()
    }

    private inline fun guard(block: () -> Unit) {
        try {
            block()
        } catch (_: Exception) {
            // Never crash the listener; nothing is logged (privacy).
        }
    }

    private class Port(private val service: SalNotificationListenerService) : NotificationPrivacyEngine.Port {
        override fun state() = NotificationPrivacyStore.state(service)

        override fun placeholderTag(packageName: String) =
            NotificationPrivacyEngine.placeholderTag(NotificationPrivacyStore.placeholderSalt(service), packageName)

        override fun appLabel(packageName: String): String? = try {
            val pm = service.packageManager
            pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString()
        } catch (_: Exception) {
            null
        }

        override fun canPostPlaceholders(mode: NotificationPrivacyPolicy.Mode) =
            NotificationPlaceholders.canPost(service, mode)

        override fun cancelSource(key: String): Boolean = try {
            service.cancelNotification(key)
            true
        } catch (_: Exception) {
            false
        }

        override fun postPlaceholder(placeholder: NotificationPrivacyEngine.Placeholder) =
            NotificationPlaceholders.post(service, placeholder)
    }

    companion object {
        @Volatile
        var connected: Boolean = false
            private set

        @Volatile
        private var instance: WeakReference<SalNotificationListenerService>? = null

        fun component(context: Context): ComponentName =
            ComponentName(context, SalNotificationListenerService::class.java)

        /** Re-evaluates the binding and the active notifications after the
         * configuration changed. */
        fun refreshBinding(context: Context) {
            val wanted = NotificationPrivacyPolicy.listenerWanted(NotificationPrivacyStore.state(context))
            try {
                val service = instance?.get()
                if (wanted && !connected) {
                    requestRebind(component(context))
                } else if (!wanted && connected) {
                    service?.requestUnbind()
                } else if (wanted && service != null) {
                    // M3: also a profile switch / rule edit: immediate re-check.
                    service.reevaluate()
                }
            } catch (_: Exception) {
                // Access not granted or the service is not ready: nothing to do.
            }
        }
    }
}
