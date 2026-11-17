package com.smartapplock.app

import android.content.ComponentName
import android.content.Context
import android.service.notification.NotificationListenerService
import java.lang.ref.WeakReference

/**
 * Phase 14 / M1: notification privacy foundation (user-granted Notification
 * access). M1 only tracks the binding and unbinds itself when no protected
 * app has privacy on (data minimization). It does not inspect, remove or
 * post notifications; the privacy modes act from M2.
 *
 * Nothing about any notification is stored or logged here.
 */
class SalNotificationListenerService : NotificationListenerService() {
    override fun onListenerConnected() {
        super.onListenerConnected()
        instance = WeakReference(this)
        connected = true
        if (!NotificationPrivacyPolicy.listenerWanted(NotificationPrivacyStore.state(this))) {
            try {
                requestUnbind()
            } catch (_: Exception) {
                // Stays bound; harmless (M1 performs no action).
            }
        }
    }

    override fun onListenerDisconnected() {
        connected = false
        instance = null
        super.onListenerDisconnected()
    }

    companion object {
        @Volatile
        var connected: Boolean = false
            private set

        @Volatile
        private var instance: WeakReference<SalNotificationListenerService>? = null

        fun component(context: Context): ComponentName =
            ComponentName(context, SalNotificationListenerService::class.java)

        /** Re-evaluates the binding after the configuration changed. */
        fun refreshBinding(context: Context) {
            val wanted = NotificationPrivacyPolicy.listenerWanted(NotificationPrivacyStore.state(context))
            try {
                if (wanted && !connected) {
                    requestRebind(component(context))
                } else if (!wanted && connected) {
                    instance?.get()?.requestUnbind()
                }
            } catch (_: Exception) {
                // Access not granted or the service is not ready: nothing to do.
            }
        }
    }
}
